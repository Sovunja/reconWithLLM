package modules

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"recon/core"
)

// ResponseFetcherModule скачивает тела HTTP-ответов для последующего
// текстового анализа (content_extractor, openapi-парсер и т.д.).
type ResponseFetcherModule struct {
	dataDir string
}

// FetchedResponse — метаданные одного скачанного ответа.
// Само тело лежит на диске по пути BodyPath.
type FetchedResponse struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	ContentType   string `json:"content_type"`
	ContentLength int    `json:"content_length"`
	BodyPath      string `json:"body_path"`
	Tool          string `json:"tool"`
	Error         string `json:"error,omitempty"`
}

func NewResponseFetcherModule(dataDir string) *ResponseFetcherModule {
	return &ResponseFetcherModule{dataDir: dataDir}
}

func (m *ResponseFetcherModule) Name() string { return "response_fetcher" }

func (m *ResponseFetcherModule) Init(ctx context.Context, kernel *core.Kernel) error {
	return nil
}

// Конфигурация (мягкие лимиты — приоритет демо).
const (
	fetcherMaxURLs        = 200              // было 50 — мало для крупных стендов
	fetcherMaxBodyBytes   = 5 * 1024 * 1024  // 5 МБ на один ответ — Angular main.js может быть таким
	fetcherTotalBudget    = 50 * 1024 * 1024 // 50 МБ суммарно
	fetcherConcurrency    = 10
	fetcherRequestTimeout = 15 * time.Second
)

// userAgents — пул реалистичных User-Agent. Случайный выбор снижает шанс
// быть забаненным WAF как очевидный бот.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
}

// isInterestingContentType определяет, стоит ли скачивать ответ для парсинга.
// Картинки, шрифты, бинарные форматы — пропускаем.
func isInterestingContentType(ct string) bool {
	ct = strings.ToLower(ct)
	prefixes := []string{
		"text/", "application/json", "application/javascript",
		"application/xml", "application/x-javascript",
		"application/x-yaml", "application/yaml",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	// Если content-type не задан — считаем интересным (часто bare-API).
	return ct == ""
}

// isInterestingStatus: 200 — данные, 301/302 — цепочки редиректов,
// 401/403 — защищённые ресурсы (важная информация для recon).
func isInterestingStatus(code int) bool {
	return code == 200 || code == 301 || code == 302 ||
		code == 401 || code == 403
}

func (m *ResponseFetcherModule) Run(ctx context.Context, scan *core.ScanContext) error {
	targets := m.collectTargets(scan)
	if len(targets) == 0 {
		log.Printf("[response_fetcher] no targets to fetch")
		return nil
	}
	if len(targets) > fetcherMaxURLs {
		log.Printf("[response_fetcher] limiting %d -> %d targets (cap)",
			len(targets), fetcherMaxURLs)
		targets = targets[:fetcherMaxURLs]
	}

	bodyDir := filepath.Join(m.dataDir, "scan-"+scan.ID, "responses")
	if err := os.MkdirAll(bodyDir, 0o755); err != nil {
		return fmt.Errorf("mkdir bodies: %w", err)
	}

	// HTTP-клиент: без follow-redirects (мы хотим видеть 301/302),
	// с InsecureSkipVerify для самоподписанных сертификатов внутри лаб.
	insecure := false
	if v, ok := scan.Config["insecure_tls"].(bool); ok {
		insecure = v
	}
	client := &http.Client{
		Timeout: fetcherRequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	// Параллельная загрузка через worker pool.
	var spent int64
	results := make([]FetchedResponse, 0, len(targets))
	var resultsMu sync.Mutex
	jobs := make(chan string, len(targets))
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < fetcherConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				if atomic.LoadInt64(&spent) > fetcherTotalBudget {
					log.Printf("[response_fetcher] global budget exceeded, stopping")
					return
				}
				if ctx.Err() != nil {
					return
				}

				fr := m.fetchOne(ctx, client, url, bodyDir)
				atomic.AddInt64(&spent, int64(fr.ContentLength))

				resultsMu.Lock()
				results = append(results, fr)
				resultsMu.Unlock()
			}
		}()
	}
	wg.Wait()

	scan.Set("fetched_responses", results)
	successCount := 0
	for _, r := range results {
		if r.Error == "" {
			successCount++
		}
	}
	log.Printf("[response_fetcher] finished: total=%d success=%d budget_used=%d/%d bytes",
		len(results), successCount, atomic.LoadInt64(&spent), int64(fetcherTotalBudget))
	return nil
}

func (m *ResponseFetcherModule) collectTargets(scan *core.ScanContext) []string {
	v, ok := scan.Get("http_services")
	if !ok {
		return nil
	}
	services, ok := v.([]HTTPService)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(services))
	for _, s := range services {
		if isInterestingStatus(s.StatusCode) && isInterestingContentType(s.ContentType) {
			out = append(out, s.URL)
		}
	}
	return out
}

// fetchOne скачивает один URL, сохраняет тело в bodyDir.
// Все ошибки прячет в FetchedResponse.Error, чтобы один битый URL
// не валил весь модуль.
func (m *ResponseFetcherModule) fetchOne(ctx context.Context, client *http.Client, url, bodyDir string) FetchedResponse {
	fr := FetchedResponse{URL: url, Tool: "response_fetcher"}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		fr.Error = "build request: " + err.Error()
		return fr
	}
	req.Header.Set("User-Agent", userAgents[time.Now().UnixNano()%int64(len(userAgents))])
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		fr.Error = "request: " + err.Error()
		return fr
	}
	defer resp.Body.Close()

	fr.StatusCode = resp.StatusCode
	fr.ContentType = resp.Header.Get("Content-Type")

	// Читаем тело с лимитом — даже если сервер обещает много, читаем только
	// fetcherMaxBodyBytes.
	limited := io.LimitReader(resp.Body, fetcherMaxBodyBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		fr.Error = "read body: " + err.Error()
		return fr
	}
	fr.ContentLength = len(body)

	// Имя файла — sha1 от URL: уникально, безопасно для файловой системы.
	hash := sha1.Sum([]byte(url))
	fname := hex.EncodeToString(hash[:]) + ".bin"
	fpath := filepath.Join(bodyDir, fname)
	if err := os.WriteFile(fpath, body, 0o644); err != nil {
		fr.Error = "write file: " + err.Error()
		return fr
	}
	fr.BodyPath = fpath

	log.Printf("[response_fetcher] fetched: %d %s (%d bytes)",
		fr.StatusCode, url, fr.ContentLength)
	return fr
}

func (m *ResponseFetcherModule) Shutdown(ctx context.Context) error { return nil }
