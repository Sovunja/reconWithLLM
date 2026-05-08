package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"recon/core"
	"recon/internal/execrunner"
)

// HttpxModule — адаптер для ProjectDiscovery httpx.
// Определяет живые веб-сервисы, технологии, версии серверов, заголовки.
//
// Особенность: httpx читает список целей из stdin или из файла. Мы будем
// собирать список из ScanContext (target + найденные endpoints/subdomains)
// и передавать через stdin.
type HttpxModule struct {
	kernel *core.Kernel
}

// HTTPService — нормализованная информация о веб-сервисе.
type HTTPService struct {
	URL          string   `json:"url"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title,omitempty"`
	WebServer    string   `json:"web_server,omitempty"`     // nginx, Apache, Express
	Technologies []string `json:"technologies,omitempty"`    // обнаруженные технологии
	ContentType  string   `json:"content_type,omitempty"`
	ContentLen   int      `json:"content_length,omitempty"`
	Tool         string   `json:"tool"`
}

func NewHttpxModule() *HttpxModule { return &HttpxModule{} }

func (m *HttpxModule) Name() string { return "httpx" }

func (m *HttpxModule) Init(ctx context.Context, kernel *core.Kernel) error {
	m.kernel = kernel
	if _, err := exec.LookPath("httpx"); err != nil {
		return fmt.Errorf("httpx binary not found in PATH: %w", err)
	}
	return nil
}

func (m *HttpxModule) Run(ctx context.Context, scan *core.ScanContext) error {
	timeout := 3 * time.Minute
	if t, ok := scan.Config["httpx_timeout"].(time.Duration); ok {
		timeout = t
	}

	// Собираем список целей: основной target + endpoints от katana + subdomains.
	targets := m.collectTargets(scan)
	if len(targets) == 0 {
		return nil
	}
	log.Printf("[httpx] starting: targets=%d timeout=%s", len(targets), timeout)

	var services []HTTPService

	onLine := func(line []byte) {
		var raw struct {
			URL           string   `json:"url"`
			StatusCode    int      `json:"status_code"`
			Title         string   `json:"title"`
			WebServer     string   `json:"webserver"`
			Tech          []string `json:"tech"`
			ContentType   string   `json:"content_type"`
			ContentLength int      `json:"content_length"`
		}
		if err := json.Unmarshal(line, &raw); err != nil {
			return
		}
		svc := HTTPService{
			URL:          raw.URL,
			StatusCode:   raw.StatusCode,
			Title:        raw.Title,
			WebServer:    raw.WebServer,
			Technologies: raw.Tech,
			ContentType:  raw.ContentType,
			ContentLen:   raw.ContentLength,
			Tool:         "httpx",
		}
		services = append(services, svc)

		log.Printf("[httpx] %d %s [%s]", raw.StatusCode, raw.URL, raw.WebServer)

		m.kernel.Publish(core.Event{
			Type:    "service.identified",
			Source:  m.Name(),
			Payload: svc,
		}, scan)
	}

	onStderr := func(line []byte) {
		log.Printf("[httpx:stderr] %s", string(line))
	}

	res, err := execrunner.Run(ctx, execrunner.Spec{
		Bin: "httpx",
		Args: []string{
			// httpx читает список из stdin автоматически, если не задан -u/-l.
			"-json",
			"-silent",
			"-status-code",
			"-title",
			"-tech-detect",
			"-server",
			"-content-type",
			"-content-length",
			"-no-color",
			"-timeout", "10",
			"-threads", "20",
		},
		Timeout:  timeout,
		Stdin:    strings.Join(targets, "\n"),
		OnLine:   onLine,
		OnStderr: onStderr,
	})
	log.Printf("[httpx] finished: services=%d duration=%s exit=%d",
		len(services), res.Duration, res.ExitCode)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("httpx failed (exit=%d, stderr=%q): %w",
			res.ExitCode, string(res.Stderr), err)
	}

	scan.Set("http_services", services)
	return nil
}

// collectTargets собирает уникальный список URL для проверки httpx.
// Берёт основной target + все endpoints от katana + subdomains (если были).
func (m *HttpxModule) collectTargets(scan *core.ScanContext) []string {
	seen := map[string]struct{}{scan.Target: {}}
	out := []string{scan.Target}

	if v, ok := scan.Get("endpoints"); ok {
		if eps, ok := v.([]Endpoint); ok {
			for _, e := range eps {
				if _, dup := seen[e.URL]; dup {
					continue
				}
				seen[e.URL] = struct{}{}
				out = append(out, e.URL)
			}
		}
	}
	if v, ok := scan.Get("subdomains"); ok {
		if subs, ok := v.([]Subdomain); ok {
			for _, s := range subs {
				url := "http://" + s.Name
				if _, dup := seen[url]; dup {
					continue
				}
				seen[url] = struct{}{}
				out = append(out, url)
			}
		}
	}
	return out
}

func (m *HttpxModule) Shutdown(ctx context.Context) error { return nil }
