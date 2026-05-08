package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"recon/core"
	"recon/internal/execrunner"
)

// EndpointValidatorModule проверяет, какие из найденных API-путей реально
// существуют. content_extractor вытащил пути из JS-кода (это просто строки
// в исходниках), но не все из них работают — какие-то унаследованы от
// прошлых версий, какие-то требуют параметров, какие-то закрыты авторизацией.
//
// Модуль берёт api_paths из ScanContext, превращает в полные URL,
// прогоняет через httpx и сохраняет в validated_endpoints с реальными
// статусами, заголовками и метаданными ответа.
type EndpointValidatorModule struct {
	kernel *core.Kernel
}

// ValidatedEndpoint — итог проверки одного эндпоинта.
type ValidatedEndpoint struct {
	URL           string `json:"url"`
	Path          string `json:"path"`           // только относительный путь, для удобства
	StatusCode    int    `json:"status_code"`
	StatusGroup   string `json:"status_group"`   // alive, auth_required, not_found, error
	ContentType   string `json:"content_type,omitempty"`
	ContentLength int    `json:"content_length,omitempty"`
	Title         string `json:"title,omitempty"`
}

func NewEndpointValidatorModule() *EndpointValidatorModule {
	return &EndpointValidatorModule{}
}

func (m *EndpointValidatorModule) Name() string { return "endpoint_validator" }

func (m *EndpointValidatorModule) Init(ctx context.Context, kernel *core.Kernel) error {
	m.kernel = kernel
	return nil
}

func (m *EndpointValidatorModule) Run(ctx context.Context, scan *core.ScanContext) error {
	// Берём API-пути от content_extractor.
	v, ok := scan.Get("extracted_content")
	if !ok {
		log.Printf("[endpoint_validator] no extracted_content in context, skipping")
		return nil
	}
	extracted, ok := v.(ExtractedContent)
	if !ok {
		log.Printf("[endpoint_validator] extracted_content has wrong type: %T", v)
		return nil
	}
	if len(extracted.APIPaths) == 0 {
		log.Printf("[endpoint_validator] no api_paths to validate, skipping")
		return nil
	}

	// Превращаем относительные пути в полные URL целевого хоста.
	base := strings.TrimRight(scan.Target, "/")
	urls := make([]string, 0, len(extracted.APIPaths))
	for _, p := range extracted.APIPaths {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		urls = append(urls, base+p)
	}

	log.Printf("[endpoint_validator] validating %d api_paths via httpx",
		len(urls))

	// Запускаем httpx со списком URL на stdin. Параметры — те же, что в
	// HttpxModule, но без -tech-detect (он нам тут не нужен, технологии
	// мы уже определили на основном проходе).
	timeout := 90 * time.Second
	if t, ok := scan.Config["validator_timeout"].(time.Duration); ok {
		timeout = t
	}

	results := make([]ValidatedEndpoint, 0, len(urls))

	onLine := func(line []byte) {
		var raw struct {
			URL           string `json:"url"`
			StatusCode    int    `json:"status_code"`
			Title         string `json:"title"`
			ContentType   string `json:"content_type"`
			ContentLength int    `json:"content_length"`
		}
		if err := json.Unmarshal(line, &raw); err != nil {
			return
		}
		ve := ValidatedEndpoint{
			URL:           raw.URL,
			Path:          strings.TrimPrefix(raw.URL, base),
			StatusCode:    raw.StatusCode,
			StatusGroup:   classifyStatus(raw.StatusCode),
			ContentType:   raw.ContentType,
			ContentLength: raw.ContentLength,
			Title:         raw.Title,
		}
		results = append(results, ve)
		log.Printf("[endpoint_validator] %d %s (%s)",
			ve.StatusCode, ve.Path, ve.StatusGroup)

		m.kernel.Publish(core.Event{
			Type:    "api.validated",
			Source:  m.Name(),
			Payload: ve,
		}, scan)
	}

	onStderr := func(line []byte) {
		log.Printf("[endpoint_validator:stderr] %s", string(line))
	}

	res, err := execrunner.Run(ctx, execrunner.Spec{
		Bin: "httpx",
		Args: []string{
			"-json",
			"-silent",
			"-status-code",
			"-title",
			"-content-type",
			"-content-length",
			"-no-color",
			"-timeout", "10",
			"-threads", "20",
			"-follow-redirects=false", // не следуем редиректам — хотим видеть исходный код
		},
		Timeout:  timeout,
		Stdin:    strings.Join(urls, "\n"),
		OnLine:   onLine,
		OnStderr: onStderr,
	})

	log.Printf("[endpoint_validator] finished: validated=%d duration=%s exit=%d",
		len(results), res.Duration, res.ExitCode)

	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		// Не считаем фатальным — пусть скан продолжается с тем, что собрали.
		log.Printf("[endpoint_validator] httpx exit non-zero (got %d results): %v",
			len(results), err)
	}

	scan.Set("validated_endpoints", results)
	return nil
}

func (m *EndpointValidatorModule) Shutdown(ctx context.Context) error { return nil }

// classifyStatus группирует статусы для удобства анализа в UI и в ИИ.
func classifyStatus(code int) string {
	switch {
	case code == 200, code == 201, code == 204:
		return "alive"
	case code == 401, code == 403:
		return "auth_required" // эндпоинт есть, но защищён — самые интересные для пентеста
	case code == 404:
		return "not_found"
	case code >= 500:
		return "server_error" // тоже интересно: значит путь настоящий, но сломан
	case code >= 300 && code < 400:
		return "redirect"
	case code == 0:
		return "unreachable"
	default:
		return fmt.Sprintf("other_%d", code)
	}
}
