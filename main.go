// Точка входа: регистрация модулей, поднятие веб-интерфейса,
// ожидание сигнала остановки. Pipeline запускается из UI, не на старте.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"recon/core"
	"recon/modules"
	"recon/modules/webui"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	// Конфигурация из окружения.
	addr := getEnv("RECON_ADDR", ":8080")
	dataDir := getEnv("RECON_DATA_DIR", "/data")

	// Pipeline-сценарии. Текущий набор модулей:
	//   hakrawler         — краулинг доступных URL
	//   common_paths      — wordlist-кандидаты (admin/api/login)
	//   httpx             — определение живых сервисов и технологий
	//   response_fetcher  — скачивание тел для последующего анализа
	//   ai_analyzer       — финальный анализ (пока заглушка)
	//   storage           — сохранение JSON-отчёта
	pipelines := map[string][]string{
		"passive_ai":    {"dns_recon", "hakrawler", "common_paths", "httpx", "response_fetcher", "content_extractor", "html_parser", "endpoint_validator", "ai_analyzer", "storage"},
		"agentic_ai":    {"dns_recon", "hakrawler", "common_paths", "httpx", "response_fetcher", "content_extractor", "html_parser", "endpoint_validator", "ai_analyzer", "storage"},
		"hypothesis_ai": {"dns_recon", "hakrawler", "common_paths", "httpx", "response_fetcher", "content_extractor", "html_parser", "endpoint_validator", "ai_analyzer", "storage"},
		"full_external": {"dns_recon", "subfinder", "hakrawler", "common_paths", "httpx", "response_fetcher", "content_extractor", "html_parser", "endpoint_validator", "ai_analyzer", "storage"},
	}

	k := core.NewKernel(logger)

	// Регистрация модулей.
	mustRegister(k, modules.NewDNSReconModule())
	mustRegister(k, modules.NewHakrawlerModule())
	mustRegister(k, modules.NewCommonPathsModule())
	mustRegister(k, modules.NewHttpxModule())
	mustRegister(k, modules.NewResponseFetcherModule(dataDir))
	mustRegister(k, modules.NewContentExtractorModule())
	mustRegister(k, modules.NewHTMLParserModule())
	mustRegister(k, modules.NewEndpointValidatorModule())
	mustRegister(k, modules.NewSubfinderModule())
	mustRegister(k, modules.NewAIAnalyzerModule())
	mustRegister(k, modules.NewStorageModule(dataDir))

	manager := core.NewScanManager(k, pipelines)
	mustRegister(k, webui.New(addr, manager))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := k.Start(ctx); err != nil {
		logger.Fatalf("kernel start: %v", err)
	}

	logger.Printf("[main] ready, web UI: http://localhost%s", addr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Printf("[main] received signal %s, shutting down...", sig)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := k.Stop(shutdownCtx); err != nil {
		logger.Printf("[main] shutdown error: %v", err)
	}
	logger.Printf("[main] bye")
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustRegister(k *core.Kernel, m core.Module) {
	if err := k.Register(m); err != nil {
		log.Fatalf("register %s: %v", m.Name(), err)
	}
}
