// Package ollama содержит HTTP-клиент для локального Ollama-сервера.
// Используется модулем анализа для отправки запросов в LLM
// (Llama 3.1 8B Instruct) во всех трёх сценариях работы системы.
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client — клиент Ollama API.
type Client struct {
	baseURL string
	model   string
	http    *http.Client
}

// NewClient создаёт клиент с указанным адресом сервера и именем модели.
// baseURL обычно приходит из переменной окружения RECON_OLLAMA_URL
// и в Docker-сети равен "http://ollama:11434".
//
// Таймаут на один запрос — 5 минут. Это много для обычного HTTP, но
// LLM-инференс на 8B модели может занять 30-90 секунд при длинном
// контексте, особенно для холодного старта (загрузка весов в VRAM).
func NewClient(baseURL, model string) *Client {
	return &Client{
		baseURL: baseURL,
		model:   model,
		http: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

// GenerateRequest — параметры одного запроса к LLM.
// Поля System и Format опциональны: если они пусты — используются
// дефолты Ollama.
type GenerateRequest struct {
	// Prompt — пользовательский запрос (обязательно).
	Prompt string

	// System — системная инструкция роли модели. Если пусто —
	// используется дефолтная инструкция модели.
	System string

	// Format — формат вывода. Если "json", Ollama применяет
	// constrained sampling, гарантирующий синтаксически валидный JSON.
	// Семантическая корректность (правильная схема, язык) — задача промпта.
	Format string

	// Temperature — температура сэмплинга. Если 0, используется дефолт модели.
	// Для аналитических задач имеет смысл понижать (0.2-0.4),
	// чтобы получать более детерминированные ответы.
	Temperature float64

	// NumCtx — размер контекстного окна в токенах. Если 0, используется
	// дефолт Ollama (обычно 2048 — что МАЛО для нашего случая).
	// Рекомендуем явно задавать 4096 или 8192 под наши промпты.
	NumCtx int
}

// generateRequestJSON — внутренняя структура для сериализации запроса.
// Не экспортируем, чтобы пользователи клиента работали с GenerateRequest.
type generateRequestJSON struct {
	Model   string                 `json:"model"`
	Prompt  string                 `json:"prompt"`
	System  string                 `json:"system,omitempty"`
	Format  string                 `json:"format,omitempty"`
	Stream  bool                   `json:"stream"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// generateResponseJSON — структура ответа Ollama при stream=false.
type generateResponseJSON struct {
	Model    string `json:"model"`
	Response string `json:"response"`
	Done     bool   `json:"done"`
	// Метрики времени в наносекундах.
	TotalDuration  int64 `json:"total_duration"`
	LoadDuration   int64 `json:"load_duration"`
	PromptEvalCount int  `json:"prompt_eval_count"`
	EvalCount      int   `json:"eval_count"`
}

// GenerateResult — итог одного вызова LLM.
type GenerateResult struct {
	Response       string        // текст ответа модели
	TotalDuration  time.Duration // полное время от запроса до ответа
	PromptTokens   int           // количество токенов во входном промпте
	ResponseTokens int           // количество токенов в ответе
}

// Generate отправляет полный запрос с system prompt, форматом и опциями.
// Возвращает текст ответа и метрики времени.
//
// Это основная функция для модуля анализа: даёт полный контроль над
// промптом и параметрами инференса.
func (c *Client) Generate(ctx context.Context, req GenerateRequest) (*GenerateResult, error) {
	options := map[string]interface{}{}
	if req.Temperature > 0 {
		options["temperature"] = req.Temperature
	}
	if req.NumCtx > 0 {
		options["num_ctx"] = req.NumCtx
	}

	payload := generateRequestJSON{
		Model:   c.model,
		Prompt:  req.Prompt,
		System:  req.System,
		Format:  req.Format,
		Stream:  false,
		Options: options,
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := c.baseURL + "/api/generate"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama returned status %d: %s",
			resp.StatusCode, string(body))
	}

	var out generateResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &GenerateResult{
		Response:       out.Response,
		TotalDuration:  time.Duration(out.TotalDuration),
		PromptTokens:   out.PromptEvalCount,
		ResponseTokens: out.EvalCount,
	}, nil
}

// Ping проверяет что Ollama-сервер доступен по baseURL.
// Используется при старте модуля, чтобы упасть с понятной ошибкой
// если ollama-контейнер не поднялся.
func (c *Client) Ping(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/", nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("ping ollama: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama ping returned status %d", resp.StatusCode)
	}
	return nil
}
