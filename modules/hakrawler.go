package modules

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"

	"recon/core"
	"recon/internal/execrunner"
)

// HakrawlerModule — адаптер для hakrawler (https://github.com/hakluke/hakrawler).
// Простой надёжный краулер: рекурсивный обход ссылок без headless-браузера,
// без jsluice, без долгих парсингов. Идеален для recon-задачи: даёт чистый
// список URL за минимальное время.
//
// Замена katana, который плохо себя вёл на минифицированных Angular SPA
// (зависал при парсинге больших JS-чанков).
type HakrawlerModule struct {
	kernel *core.Kernel
}

// Endpoint — нормализованная сущность найденного URL/эндпоинта.
// Используется всеми модулями, которые что-то находят: hakrawler (краулер),
// common_paths (wordlist), httpx (для построения списка целей).
type Endpoint struct {
	URL    string `json:"url"`
	Method string `json:"method,omitempty"` // GET, POST и т.д.
	Source string `json:"source,omitempty"` // как был найден: crawl, wordlist
	Tag    string `json:"tag,omitempty"`    // дополнительная метка
	Tool   string `json:"tool"`             // инструмент-сборщик
}

func NewHakrawlerModule() *HakrawlerModule { return &HakrawlerModule{} }

func (m *HakrawlerModule) Name() string { return "hakrawler" }

func (m *HakrawlerModule) Init(ctx context.Context, kernel *core.Kernel) error {
	m.kernel = kernel
	if _, err := exec.LookPath("hakrawler"); err != nil {
		return fmt.Errorf("hakrawler binary not found in PATH: %w", err)
	}
	return nil
}

func (m *HakrawlerModule) Run(ctx context.Context, scan *core.ScanContext) error {
	timeout := 60 * time.Second
	if t, ok := scan.Config["hakrawler_timeout"].(time.Duration); ok {
		timeout = t
	}
	depth := 2
	if d, ok := scan.Config["hakrawler_depth"].(int); ok {
		depth = d
	}

	var endpoints []Endpoint
	foundCount := 0

	// Hakrawler выводит просто URL по строке, без структуры.
	onLine := func(line []byte) {
		url := string(line)
		if url == "" {
			return
		}
		ep := Endpoint{
			URL:    url,
			Method: "GET",
			Source: "crawl",
			Tool:   "hakrawler",
		}
		endpoints = append(endpoints, ep)
		foundCount++
		log.Printf("[hakrawler] found: %s", url)

		m.kernel.Publish(core.Event{
			Type:    "endpoint.found",
			Source:  m.Name(),
			Payload: ep,
		}, scan)
	}

	onStderr := func(line []byte) {
		log.Printf("[hakrawler:stderr] %s", string(line))
	}

	log.Printf("[hakrawler] starting: target=%s depth=%d timeout=%s",
		scan.Target, depth, timeout)

	res, err := execrunner.Run(ctx, execrunner.Spec{
		Bin: "hakrawler",
		Args: []string{
			"-d", fmt.Sprintf("%d", depth), // глубина обхода
			"-t", "20",                     // threads
			"-timeout", "5",                // таймаут на запрос
			"-subs",                        // включать поддомены
			"-u",                           // только уникальные URL
		},
		Timeout:  timeout,
		Stdin:    scan.Target,  // hakrawler читает целевые URL из stdin
		OnLine:   onLine,
		OnStderr: onStderr,
	})

	log.Printf("[hakrawler] finished: found=%d duration=%s exit=%d",
		foundCount, res.Duration, res.ExitCode)

	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Не считаем ненулевой exit code фатальным — hakrawler иногда
		// выходит с ошибкой, успев собрать часть данных.
		log.Printf("[hakrawler] non-zero exit (got %d results anyway): %v",
			foundCount, err)
	}

	scan.Set("endpoints", endpoints)
	return nil
}

func (m *HakrawlerModule) Shutdown(ctx context.Context) error { return nil }
