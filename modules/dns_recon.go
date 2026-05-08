package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"recon/core"
	"recon/internal/execrunner"
)

// DNSReconModule — DNS-разведка через ProjectDiscovery dnsx.
// Закрывает позицию таблицы 1 «определение почтовых сервисов»
// (через MX-записи) и собирает дополнительный контекст:
// IP-адреса (A/AAAA), namespace-серверы (NS), TXT-записи
// (часто содержат SPF, упоминания Google Workspace, Office 365).
//
// Для целевых хостов внутри Docker-сети (juiceshop) DNS-разведка
// не даёт ничего полезного — модуль элегантно завершается без
// данных и не ломает pipeline. Для публичных доменов даёт настоящий
// recon-результат.
type DNSReconModule struct {
	kernel *core.Kernel
}

// DNSRecord — нормализованная DNS-запись.
type DNSRecord struct {
	Host  string   `json:"host"`
	Type  string   `json:"type"`  // A, AAAA, MX, TXT, NS, CNAME
	Value []string `json:"value"`
}

// MailService — выделенный объект для почтовых сервисов
// (наиболее ценная часть DNS-разведки для recon).
type MailService struct {
	Host     string `json:"host"`
	Provider string `json:"provider"` // распознанный провайдер: "Google", "Microsoft", и т.д.
	MX       string `json:"mx"`
}

func NewDNSReconModule() *DNSReconModule { return &DNSReconModule{} }

func (m *DNSReconModule) Name() string { return "dns_recon" }

func (m *DNSReconModule) Init(ctx context.Context, kernel *core.Kernel) error {
	m.kernel = kernel
	if _, err := exec.LookPath("dnsx"); err != nil {
		return fmt.Errorf("dnsx binary not found in PATH: %w", err)
	}
	return nil
}

func (m *DNSReconModule) Run(ctx context.Context, scan *core.ScanContext) error {
	host := dnsExtractHost(scan.Target)
	if host == "" {
		log.Printf("[dns_recon] cannot extract host from target=%s", scan.Target)
		return nil
	}

	// Не имеет смысла резолвить локальные имена внутри Docker-сети
	// (juiceshop, recon, localhost) — DNS отдаст внутренний IP сети,
	// MX/TXT/NS будут пусты. Просто завершаемся.
	if isInternalHost(host) {
		log.Printf("[dns_recon] target host %q is internal, skipping DNS recon", host)
		return nil
	}

	timeout := 30 * time.Second
	if t, ok := scan.Config["dnsx_timeout"].(time.Duration); ok {
		timeout = t
	}

	log.Printf("[dns_recon] resolving %s (A/AAAA/MX/TXT/NS/CNAME)", host)

	var records []DNSRecord
	var mailServices []MailService

	onLine := func(line []byte) {
		var raw struct {
			Host  string   `json:"host"`
			A     []string `json:"a"`
			AAAA  []string `json:"aaaa"`
			MX    []string `json:"mx"`
			TXT   []string `json:"txt"`
			NS    []string `json:"ns"`
			CNAME []string `json:"cname"`
		}
		if err := json.Unmarshal(line, &raw); err != nil {
			return
		}

		if len(raw.A) > 0 {
			records = append(records, DNSRecord{Host: raw.Host, Type: "A", Value: raw.A})
		}
		if len(raw.AAAA) > 0 {
			records = append(records, DNSRecord{Host: raw.Host, Type: "AAAA", Value: raw.AAAA})
		}
		if len(raw.NS) > 0 {
			records = append(records, DNSRecord{Host: raw.Host, Type: "NS", Value: raw.NS})
		}
		if len(raw.CNAME) > 0 {
			records = append(records, DNSRecord{Host: raw.Host, Type: "CNAME", Value: raw.CNAME})
		}
		if len(raw.TXT) > 0 {
			records = append(records, DNSRecord{Host: raw.Host, Type: "TXT", Value: raw.TXT})
		}
		if len(raw.MX) > 0 {
			records = append(records, DNSRecord{Host: raw.Host, Type: "MX", Value: raw.MX})
			for _, mx := range raw.MX {
				mailServices = append(mailServices, MailService{
					Host:     raw.Host,
					MX:       mx,
					Provider: identifyMailProvider(mx),
				})
			}
		}
	}

	onStderr := func(line []byte) {
		log.Printf("[dns_recon:stderr] %s", string(line))
	}

	res, err := execrunner.Run(ctx, execrunner.Spec{
		Bin: "dnsx",
		Args: []string{
			"-silent",
			"-json",
			"-a", "-aaaa", "-mx", "-txt", "-ns", "-cname",
			"-resp",
		},
		Timeout:  timeout,
		Stdin:    host,
		OnLine:   onLine,
		OnStderr: onStderr,
	})

	log.Printf("[dns_recon] finished: records=%d mail_services=%d duration=%s exit=%d",
		len(records), len(mailServices), res.Duration, res.ExitCode)

	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}

	scan.Set("dns_records", records)
	if len(mailServices) > 0 {
		scan.Set("mail_services", mailServices)
	}
	return nil
}

func (m *DNSReconModule) Shutdown(ctx context.Context) error { return nil }

// dnsExtractHost — версия для DNS-модуля (не конфликтует с extractHost
// из других модулей, если они появятся).
func dnsExtractHost(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://"))
	}
	return u.Hostname()
}

// isInternalHost определяет, что хост — это внутренний адрес Docker-сети
// или localhost, для которых публичная DNS-разведка бессмысленна.
func isInternalHost(host string) bool {
	low := strings.ToLower(host)
	if low == "localhost" || strings.HasPrefix(low, "127.") {
		return true
	}
	// Docker-сетевые имена не содержат точки.
	if !strings.Contains(low, ".") {
		return true
	}
	if strings.HasPrefix(low, "10.") || strings.HasPrefix(low, "192.168.") {
		return true
	}
	return false
}

// identifyMailProvider распознаёт известных почтовых провайдеров
// по характерным суффиксам MX-записей.
func identifyMailProvider(mx string) string {
	low := strings.ToLower(mx)
	switch {
	case strings.Contains(low, "google") || strings.Contains(low, "gmail"):
		return "Google Workspace"
	case strings.Contains(low, "outlook") || strings.Contains(low, "office365") ||
		strings.Contains(low, "protection.outlook"):
		return "Microsoft 365"
	case strings.Contains(low, "yandex"):
		return "Yandex"
	case strings.Contains(low, "mail.ru"):
		return "Mail.ru"
	case strings.Contains(low, "zoho"):
		return "Zoho Mail"
	case strings.Contains(low, "amazonaws"):
		return "Amazon SES"
	case strings.Contains(low, "mailgun"):
		return "Mailgun"
	case strings.Contains(low, "sendgrid"):
		return "SendGrid"
	}
	return ""
}
