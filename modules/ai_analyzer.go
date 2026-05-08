package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"recon/core"
	"recon/internal/ollama"
)

// AIAnalyzerModule — модуль ИИ-анализа recon-данных.
// Реализует core.Module и core.EventSubscriber.
//
// Текущая реализация поддерживает Сценарий 1 (passive_ai): после завершения
// сбора данных всеми модулями pipeline'а формируется компактная сводка,
// отправляется в локальную Llama 3.1 8B через Ollama, и результат
// складывается в ScanContext под ключом ai_analysis.
//
// Сценарии agentic_ai (через шину событий) и hypothesis_ai будут
// реализованы в следующих этапах работы.
type AIAnalyzerModule struct {
	kernel *core.Kernel
	llm    *ollama.Client
	online bool // true если Ping в Init прошёл успешно
}

func NewAIAnalyzerModule() *AIAnalyzerModule { return &AIAnalyzerModule{} }

func (m *AIAnalyzerModule) Name() string { return "ai_analyzer" }

func (m *AIAnalyzerModule) Init(ctx context.Context, kernel *core.Kernel) error {
	m.kernel = kernel
	baseURL := getenv("RECON_OLLAMA_URL", "http://ollama:11434")
	model := getenv("RECON_OLLAMA_MODEL", "llama3.1:8b")
	m.llm = ollama.NewClient(baseURL, model)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := m.llm.Ping(pingCtx); err != nil {
		log.Printf("[ai_analyzer] WARN: cannot reach ollama at %s: %v", baseURL, err)
		log.Printf("[ai_analyzer] module will fall back to stub responses")
		m.online = false
	} else {
		log.Printf("[ai_analyzer] connected to ollama at %s, model=%s", baseURL, model)
		m.online = true
	}
	return nil
}

// AIAnalysis — типизированный результат анализа от LLM в Сценарии 1.
// Структура жёстко фиксирована в systemPromptPassive, чтобы модель
// возвращала JSON, который можно прямо отдать в UI и в отчёт.
//
// Намеренно нет полей risk_observations и recommendations — это
// территория Сценария 3 (hypothesis_ai). В Сценарии 1 модель работает
// как нейтральный аналитический помощник.
type AIAnalysis struct {
	Summary         string           `json:"summary"`
	TechnologyStack TechnologyStack  `json:"technology_stack"`
	SurfaceOverview SurfaceOverview  `json:"surface_overview"`
	NotableFindings []NotableFinding `json:"notable_findings"`
}

type TechnologyStack struct {
	Description string   `json:"description"`
	Components  []string `json:"components"`
}

// SurfaceOverview — нейтральное описание поверхности без оценок
// "опасно/безопасно". Только факты и цифры.
type SurfaceOverview struct {
	Scale              string `json:"scale"`               // подсчёты, распределения статусов
	PublicEndpoints    string `json:"public_endpoints"`    // что доступно без авторизации
	ProtectedEndpoints string `json:"protected_endpoints"` // что требует авторизации
	ExtractedEntities  string `json:"extracted_entities"`  // обзор контактов, имён, версий
}

// NotableFinding — отдельный примечательный факт. Не "уязвимость",
// а наблюдение, на которое стоит обратить внимание человеку-аналитику.
type NotableFinding struct {
	Category    string `json:"category"`    // endpoints | technology | content | structure
	Observation string `json:"observation"` // нейтральное описание факта
	Evidence    string `json:"evidence"`    // конкретная ссылка на данные отчёта
}

// HypothesisAnalysis — типизированный результат анализа от LLM
// в Сценарии 3 (hypothesis_ai). В отличие от AIAnalysis, этот
// результат содержит экспертные оценки: гипотезы об уязвимостях,
// конкретные векторы атак и приоритизированный план шагов.
//
// Ключи JSON остаются английскими (для стабильного парсинга
// модели Llama 3.1 8B), значения полей — на русском языке.
type HypothesisAnalysis struct {
	Summary     string         `json:"summary"`     // общая оценка цели в 2-3 предложениях
	Hypotheses  []Hypothesis   `json:"hypotheses"`  // потенциальные уязвимости
	AttackVectors []AttackVector `json:"attack_vectors"` // конкретные векторы атак с шагами
	NextSteps   []NextStep     `json:"next_steps"`  // приоритизированный план
}

// Hypothesis — гипотеза о потенциальной уязвимости.
type Hypothesis struct {
	Severity    string `json:"severity"`    // low | medium | high | critical
	Title       string `json:"title"`       // короткий заголовок
	Description string `json:"description"` // развёрнутое описание гипотезы
	Evidence    string `json:"evidence"`    // на каких артефактах из отчёта основана
	VectorType  string `json:"vector_type"` // тип вектора (injection, broken-auth, idor и т.п.)
}

// AttackVector — конкретный вектор атаки с предлагаемыми шагами проверки.
type AttackVector struct {
	Title       string   `json:"title"`       // название вектора
	Target      string   `json:"target"`      // целевой эндпоинт или компонент
	Description string   `json:"description"` // в чём суть атаки
	Steps       []string `json:"steps"`       // конкретные шаги для пентестера
}

// NextStep — приоритизированная рекомендация для следующих этапов работы.
type NextStep struct {
	Priority string `json:"priority"` // 1 — самый высокий
	Action   string `json:"action"`   // что нужно сделать
	Reason   string `json:"reason"`   // почему это важно
}

// Run — реализация Сценария 1 (passive_ai).
// Формирует сводку, отправляет в LLM, парсит ответ, кладёт в контекст.
func (m *AIAnalyzerModule) Run(ctx context.Context, scan *core.ScanContext) error {
	// Если Ollama недоступна — возвращаем заглушку, чтобы система
	// продолжала работать. Это удобно для отладки pipeline'а без LLM.
	if !m.online {
		scan.Set("ai_analysis", map[string]string{
			"summary": "stub: ollama unreachable",
		})
		return nil
	}

	// Switch по сценариям: каждый сценарий имеет свой системный промпт
	// и свой тип результата. Общая логика вызова LLM — в runAutorun.
	switch scan.Scenario {
	case "passive_ai":
		return m.runPassiveAutorun(ctx, scan)
	case "hypothesis_ai":
		return m.runHypothesisAutorun(ctx, scan)
	default:
		log.Printf("[ai_analyzer] scenario %s not yet implemented, skipping", scan.Scenario)
		scan.Set("ai_analysis", map[string]string{
			"summary": fmt.Sprintf("scenario %s not yet implemented", scan.Scenario),
		})
		return nil
	}
}

// runPassiveAutorun — Сценарий 1: нейтральный аналитический отчёт.
func (m *AIAnalyzerModule) runPassiveAutorun(ctx context.Context, scan *core.ScanContext) error {
	summary := buildScanSummary(scan)
	log.Printf("[ai_analyzer] passive_ai: sending %d chars of summary to LLM", len(summary))

	llmCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	res, err := m.llm.Generate(llmCtx, ollama.GenerateRequest{
		System:      systemPromptPassive,
		Prompt:      summary,
		Format:      "json",
		Temperature: 0.3,
		NumCtx:      8192,
	})
	if err != nil {
		log.Printf("[ai_analyzer] passive_ai LLM call failed: %v", err)
		scan.Set("ai_analysis", map[string]string{"summary": "LLM call failed: " + err.Error()})
		return nil
	}

	log.Printf("[ai_analyzer] passive_ai LLM responded in %s, prompt_tokens=%d response_tokens=%d",
		res.TotalDuration, res.PromptTokens, res.ResponseTokens)

	var analysis AIAnalysis
	if err := json.Unmarshal([]byte(res.Response), &analysis); err != nil {
		log.Printf("[ai_analyzer] passive_ai: cannot parse LLM JSON: %v", err)
		log.Printf("[ai_analyzer] raw response: %s", truncate(res.Response, 500))
		scan.Set("ai_analysis", map[string]interface{}{
			"summary":      "LLM returned invalid JSON",
			"raw_response": res.Response,
		})
		return nil
	}

	// Конвертируем типизированную структуру в map[string]interface{}
	// для рендера в html/template. Шаблон обращается к полям через
	// JSON-имена (с маленькой буквы), а не через имена полей Go.
	scan.Set("ai_analysis", structToMap(analysis))
	return nil
}

// runHypothesisAutorun — Сценарий 3: экспертный анализ с гипотезами
// о потенциальных уязвимостях, векторами атак и приоритизированным
// планом дальнейших шагов.
func (m *AIAnalyzerModule) runHypothesisAutorun(ctx context.Context, scan *core.ScanContext) error {
	summary := buildScanSummary(scan)
	log.Printf("[ai_analyzer] hypothesis_ai: sending %d chars of summary to LLM", len(summary))

	// Температура чуть выше чем в passive_ai — экспертный анализ
	// предполагает связывание разрозненных артефактов, что требует
	// большей креативности модели. Контекст увеличен для длинных ответов.
	llmCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	res, err := m.llm.Generate(llmCtx, ollama.GenerateRequest{
		System:      systemPromptHypothesis,
		Prompt:      summary,
		Format:      "json",
		Temperature: 0.5,
		NumCtx:      8192,
	})
	if err != nil {
		log.Printf("[ai_analyzer] hypothesis_ai LLM call failed: %v", err)
		scan.Set("ai_analysis", map[string]string{"summary": "LLM call failed: " + err.Error()})
		return nil
	}

	log.Printf("[ai_analyzer] hypothesis_ai LLM responded in %s, prompt_tokens=%d response_tokens=%d",
		res.TotalDuration, res.PromptTokens, res.ResponseTokens)

	var analysis HypothesisAnalysis
	if err := json.Unmarshal([]byte(res.Response), &analysis); err != nil {
		log.Printf("[ai_analyzer] hypothesis_ai: cannot parse LLM JSON: %v", err)
		log.Printf("[ai_analyzer] raw response: %s", truncate(res.Response, 500))
		scan.Set("ai_analysis", map[string]interface{}{
			"summary":      "LLM returned invalid JSON",
			"raw_response": res.Response,
		})
		return nil
	}

	scan.Set("ai_analysis", structToMap(analysis))
	return nil
}

func (m *AIAnalyzerModule) Shutdown(ctx context.Context) error { return nil }

// --- EventSubscriber: для Сценария 2 (agentic_ai), пока заглушка ---

func (m *AIAnalyzerModule) Subscriptions() []string {
	return []string{"endpoint.found", "service.identified"}
}

func (m *AIAnalyzerModule) HandleEvent(ctx context.Context, ev core.Event, scan *core.ScanContext) error {
	if scan.Scenario != "agentic_ai" {
		return nil
	}
	// Реальная агентная логика — на этапе 5.
	return nil
}

// --- Q&A интерфейс для Сценария 1 (passive_ai) ---

// Ask отправляет в LLM один пользовательский вопрос с учётом истории
// диалога и собранных данных скана. Возвращает текст ответа.
//
// Контекст подаётся по трёхуровневой стратегии:
//   1) Всегда — компактная сводка по сканированию.
//   2) По ключевым словам в вопросе — сырые данные релевантной секции.
//   3) Fallback — только сводка, если ключевые слова не сработали.
//
// История ограничена последними N сообщениями, чтобы не превысить
// контекстное окно при долгом диалоге.
func (m *AIAnalyzerModule) Ask(
	ctx context.Context,
	scan *core.ScanContext,
	history []core.ChatMessage,
	question string,
) (string, error) {
	if !m.online {
		return "", fmt.Errorf("LLM unavailable: ollama is offline")
	}

	// Уровень 1 — сводка, всегда.
	summary := buildScanSummary(scan)

	// Уровень 2 — сырые секции по ключевым словам.
	rawSections := pickRelevantSections(scan, question)

	// Формируем prompt: контекст + история + текущий вопрос.
	var sb strings.Builder
	sb.WriteString("=== Reconnaissance summary ===\n")
	sb.WriteString(summary)
	sb.WriteString("\n")

	if rawSections != "" {
		sb.WriteString("=== Detailed data (raw JSON) ===\n")
		sb.WriteString(rawSections)
		sb.WriteString("\n\n")
	}

	// История — последние 6 сообщений (3 пары вопрос/ответ).
	const maxHistoryMessages = 6
	if len(history) > maxHistoryMessages {
		history = history[len(history)-maxHistoryMessages:]
	}
	if len(history) > 0 {
		sb.WriteString("=== Conversation so far ===\n")
		for _, msg := range history {
			role := "User"
			if msg.Role == "assistant" {
				role = "Assistant"
			}
			fmt.Fprintf(&sb, "%s: %s\n", role, msg.Content)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("=== New user question ===\n")
	sb.WriteString(question)

	log.Printf("[ai_analyzer] Q&A: prompt size %d chars, history %d msgs",
		sb.Len(), len(history))

	llmCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	// Выбор системного промпта зависит от сценария скана.
	// В hypothesis_ai модель работает как эксперт-пентестер,
	// в passive_ai (и любом другом) — как аналитический навигатор.
	systemPrompt := systemPromptQA
	if scan.Scenario == "hypothesis_ai" {
		systemPrompt = systemPromptHypothesisQA
	}

	res, err := m.llm.Generate(llmCtx, ollama.GenerateRequest{
		System:      systemPrompt,
		Prompt:      sb.String(),
		Temperature: 0.4, // чуть выше чем в autorun, диалог допускает разнообразие
		NumCtx:      8192,
		// format: "json" не используем — Q&A отдаёт обычный текст с markdown.
	})
	if err != nil {
		return "", fmt.Errorf("LLM call failed: %w", err)
	}

	log.Printf("[ai_analyzer] Q&A LLM responded in %s, prompt_tokens=%d response_tokens=%d",
		res.TotalDuration, res.PromptTokens, res.ResponseTokens)

	return strings.TrimSpace(res.Response), nil
}

// systemPromptQA — системный промпт для Q&A режима в Сценарии 1.
const systemPromptQA = `You are an analytical assistant helping a penetration tester
explore reconnaissance data about a target. You have access to:
1. A summary of the reconnaissance report.
2. Optionally, raw JSON of specific sections relevant to the question.
3. The conversation history so far.

Rules:
- Answer based ONLY on the data provided. If the data does not contain
  the answer, say so explicitly.
- The user may ask in English or Russian. Reply in the same language
  the user used.
- Be concise but complete. Use markdown formatting when helpful
  (bullet lists, tables, inline code for paths and headers).
- Do NOT invent endpoints, technologies, emails, or entities that are
  not in the data.
- You are a data navigator, not a security expert. Stay descriptive,
  do not suggest exploits or rate vulnerabilities by severity.`

// pickRelevantSections возвращает сырые JSON-куски ScanContext, релевантные
// вопросу. Если ничего не подошло — возвращает пустую строку, и тогда
// LLM работает только со сводкой.
func pickRelevantSections(scan *core.ScanContext, question string) string {
	q := strings.ToLower(question)

	// Карта ключевых слов на ключи ScanContext, которые стоит подгрузить.
	type rule struct {
		keywords []string
		ctxKeys  []string
	}
	rules := []rule{
		{
			keywords: []string{"email", "почт", "контакт", "phone", "телефон", "name", "имя", "сотрудник"},
			ctxKeys:  []string{"extracted_content", "html_parsed"},
		},
		{
			keywords: []string{"endpoint", "api", "url", "path", "маршрут", "эндпоинт"},
			ctxKeys:  []string{"validated_endpoints", "endpoints"},
		},
		{
			keywords: []string{"tech", "cms", "framework", "технолог", "стек", "версии", "version"},
			ctxKeys:  []string{"extracted_content", "http_services"},
		},
		{
			keywords: []string{"dns", "mx", "mail server", "почтов"},
			ctxKeys:  []string{"dns_records", "mail_services"},
		},
		{
			keywords: []string{"form", "форм", "login", "signup", "вход", "регистрац"},
			ctxKeys:  []string{"html_parsed"},
		},
		{
			keywords: []string{"header", "заголов", "status", "код", "http"},
			ctxKeys:  []string{"http_services"},
		},
	}

	// Собираем уникальное множество ключей которые подгрузим.
	keysToLoad := map[string]bool{}
	for _, r := range rules {
		for _, kw := range r.keywords {
			if strings.Contains(q, kw) {
				for _, k := range r.ctxKeys {
					keysToLoad[k] = true
				}
				break
			}
		}
	}
	if len(keysToLoad) == 0 {
		return ""
	}

	// Сериализуем релевантные секции.
	var sb strings.Builder
	for key := range keysToLoad {
		v, ok := scan.Get(key)
		if !ok {
			continue
		}
		// Усекаем большие массивы, чтобы не вылететь за контекст.
		v = truncateForContext(key, v)
		j, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			continue
		}
		fmt.Fprintf(&sb, "--- %s ---\n%s\n\n", key, string(j))
	}
	return sb.String()
}

// truncateForContext усекает крупные массивы, чтобы не превысить
// контекстное окно. Для слайсов длиной > N оставляем первые N элементов.
func truncateForContext(key string, v interface{}) interface{} {
	const maxItems = 50

	switch typed := v.(type) {
	case []HTTPService:
		if len(typed) > maxItems {
			return typed[:maxItems]
		}
	case []ValidatedEndpoint:
		if len(typed) > maxItems {
			return typed[:maxItems]
		}
	case []Endpoint:
		if len(typed) > maxItems {
			return typed[:maxItems]
		}
	case []DNSRecord:
		if len(typed) > maxItems {
			return typed[:maxItems]
		}
	}
	return v
}

// systemPromptPassive — системный промпт для Сценария 1 (passive_ai).
//
// Роль модели — нейтральный аналитический помощник, который структурирует
// собранные данные и помогает в них ориентироваться. Намеренно избегает
// оценочных суждений (severity, рекомендаций по эксплуатации, гипотез
// о векторах атак) — это территория Сценария 3 (hypothesis_ai).
//
// Цель — дать пентестеру удобный для чтения обзор и подготовить почву
// для последующих интерактивных запросов через Q&A интерфейс.
//
// Промпт на русском языке, текстовые значения JSON ожидаются на русском,
// имена ключей остаются английскими для стабильного парсинга — это
// гибридная схема, аналогичная Сценарию 3 (hypothesis_ai).
const systemPromptPassive = `Ты — аналитик данных разведки. На вход ты получаешь
структурированные данные, собранные автоматическими инструментами разведки
веб-цели. Твоя роль — помочь пентестеру ориентироваться в этих данных и
понять их, а НЕ оценивать уязвимости, предлагать эксплойты или рекомендовать
наступательные действия. Оценка рисков выполняется отдельным
специализированным модулем (Сценарий 3).

Что нужно сделать:
1. Кратко описать, что представляет собой цель, и какой технологический
   стек обнаружен.
2. Описать поверхность атаки в терминах фактов и количеств (публичные
   и защищённые эндпоинты, масштаб, типы контента) — без оценочных суждений.
3. Выделить примечательные находки: эндпоинты, сущности, структурные
   особенности, на которые стоит обратить внимание человеку-аналитику.
   Оставайся в описательном тоне, НЕ классифицируй их по severity и
   НЕ предлагай шагов эксплуатации.

Отвечай СТРОГО валидным JSON по следующей схеме (без markdown, без
комментариев вне JSON):
{
  "summary": "обзор цели в 2-3 предложениях на русском: что за цель, стек, масштаб поверхности",
  "technology_stack": {
    "description": "короткое описание стека на русском",
    "components": ["tech1", "tech2"]
  },
  "surface_overview": {
    "scale": "количество эндпоинтов и распределение статус-кодов как факты, на русском",
    "public_endpoints": "фактическое описание того, что доступно без авторизации, на русском",
    "protected_endpoints": "фактическое описание защищённых эндпоинтов, на русском",
    "extracted_entities": "сводка по найденным email, именам, версиям, контактам, на русском"
  },
  "notable_findings": [
    {
      "category": "endpoints | technology | content | structure",
      "observation": "нейтральное фактическое описание того, что выделяется, на русском",
      "evidence": "конкретный эндпоинт, заголовок или значение из данных"
    }
  ]
}

Важно:
- Все утверждения должны опираться на реальные данные из ввода. Не
  выдумывай эндпоинты, технологии или сущности, которых нет в отчёте.
- Имена ключей JSON всегда на английском (summary, technology_stack,
  description, components, surface_overview, scale, public_endpoints,
  protected_endpoints, extracted_entities, notable_findings, category,
  observation, evidence).
- Названия категорий в notable_findings (endpoints, technology, content,
  structure) — на английском как технические идентификаторы.
- Названия технологий в technology_stack.components — на английском
  (Node.js, Material Design, TypeScript и т.п.).
- Текстовые значения остальных полей — на русском.
- Не используй слова «уязвимость», «эксплойт», «атакующий», «опасный»,
  «рискованный» — оставайся строго в описательном тоне.`

// systemPromptHypothesis — системный промпт для Сценария 3 (hypothesis_ai),
// автоматический режим. В отличие от Сценария 1, здесь модель работает
// в роли эксперта по offensive security: формирует гипотезы о потенциальных
// уязвимостях, конкретные векторы атак с шагами проверки, приоритизированный
// план дальнейших шагов.
//
// Промпт написан на русском языке, ответ ожидается также на русском,
// но имена ключей JSON остаются английскими для стабильного парсинга.
const systemPromptHypothesis = `Ты — эксперт по тестированию на проникновение.
На вход ты получишь структурированные данные разведки веб-приложения,
собранные автоматическими инструментами. Твоя задача — провести экспертный
анализ этих данных и сформировать рабочие гипотезы для следующих этапов
пентеста.

Что нужно сделать:
1. Сформулировать гипотезы о потенциальных уязвимостях с указанием severity
   (low / medium / high / critical) и привязкой к конкретным артефактам отчёта.
   Тип вектора указывай на английском (injection, broken-auth, idor,
   ssrf, xss, csrf, path-traversal, info-disclosure, race-condition и т.п.) —
   это технический идентификатор для дальнейшей классификации.
2. Описать конкретные векторы атак: какой эндпоинт атаковать, какую
   технику применить, последовательность шагов проверки.
3. Составить приоритизированный план дальнейших шагов пентеста.

Отвечай СТРОГО валидным JSON по следующей схеме (без markdown, без
комментариев вне JSON):
{
  "summary": "общая оценка цели в 2-3 предложениях, на русском",
  "hypotheses": [
    {
      "severity": "low|medium|high|critical",
      "title": "короткий заголовок гипотезы на русском",
      "description": "развёрнутое описание гипотезы на русском",
      "evidence": "ссылка на конкретный артефакт отчёта",
      "vector_type": "тип вектора латиницей: injection, idor, broken-auth и т.п."
    }
  ],
  "attack_vectors": [
    {
      "title": "название вектора на русском",
      "target": "целевой эндпоинт или компонент",
      "description": "описание сути атаки на русском",
      "steps": [
        "шаг 1 на русском",
        "шаг 2 на русском"
      ]
    }
  ],
  "next_steps": [
    {
      "priority": "1",
      "action": "что нужно проверить, на русском",
      "reason": "почему это приоритетно, на русском"
    }
  ]
}

Важно:
- Все гипотезы должны опираться на реальные данные из отчёта.
- Не выдумывай эндпоинты, технологии или сущности, которых нет в отчёте.
- Имена ключей JSON всегда на английском (summary, hypotheses,
  attack_vectors, next_steps, severity, title, description, evidence,
  vector_type, target, steps, priority, action, reason).
- Текстовые значения полей — на русском.
- Тип вектора (vector_type) — короткий идентификатор латиницей.`

// systemPromptHypothesisQA — системный промпт для Q&A режима в Сценарии 3.
// Модель работает как эксперт по пентесту, отвечающий на конкретные
// вопросы пользователя по результатам анализа.
const systemPromptHypothesisQA = `Ты — эксперт по тестированию на проникновение,
помогающий пентестеру в работе с собранными данными разведки веб-приложения.
У тебя есть доступ к:
1. Сводке отчёта о разведке.
2. По релевантным ключевым словам — сырые JSON-данные конкретных секций отчёта.
3. История диалога с пользователем.

Правила:
- Отвечай только на основании предоставленных данных. Если данных
  для ответа недостаточно, прямо так и скажи.
- Пользователь может задавать вопросы на русском или английском языке.
  Отвечай на том же языке, на котором задан вопрос.
- Используй markdown для форматирования (списки, таблицы, inline code
  для путей и заголовков).
- В отличие от обычного аналитика, ты можешь высказывать экспертные
  суждения о потенциальных уязвимостях, оценивать риски, предлагать
  конкретные техники атак и приоритеты.
- Не выдумывай эндпоинты, технологии или сущности, которых нет в данных.`

// --- Подготовка сводки данных для LLM ---

// buildScanSummary преобразует ScanContext в компактный текстовый
// блок для LLM. Сырые JSON-структуры не передаются: они слишком
// объёмны и дают модели много шума. Вместо этого формируется
// человекочитаемая сводка с выделенными секциями.
func buildScanSummary(scan *core.ScanContext) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Target: %s\n", scan.Target)
	fmt.Fprintf(&sb, "Scenario: %s\n\n", scan.Scenario)

	// HTTP-сервисы: агрегированные коды ответов и примеры заголовков.
	if v, ok := scan.Get("http_services"); ok {
		if svcs, ok := v.([]HTTPService); ok && len(svcs) > 0 {
			sb.WriteString("== HTTP services ==\n")
			fmt.Fprintf(&sb, "Total: %d endpoints scanned\n", len(svcs))
			codes := map[int]int{}
			titles := map[string]int{}
			for _, s := range svcs {
				codes[s.StatusCode]++
				if s.Title != "" {
					titles[s.Title]++
				}
			}
			sb.WriteString("Status codes: ")
			sb.WriteString(formatCodes(codes))
			sb.WriteString("\n")
			if len(titles) > 0 {
				sb.WriteString("Sample titles: ")
				sb.WriteString(topItems(titles, 5))
				sb.WriteString("\n")
			}
			sb.WriteString("\n")
		}
	}

	// Валидированные API: разбивка по группам с поимённым списком путей.
	// Для alive и auth_required перечисляем ВСЕ эндпоинты построчно —
	// модель должна видеть точные пути, чтобы не выдумывать их в анализе.
	// Для server_error и прочих групп даём агрегированный список.
	if v, ok := scan.Get("validated_endpoints"); ok {
		if eps, ok := v.([]ValidatedEndpoint); ok && len(eps) > 0 {
			sb.WriteString("== Validated API paths ==\n")
			groups := map[string][]string{}
			for _, e := range eps {
				groups[e.StatusGroup] = append(groups[e.StatusGroup], e.Path)
			}
			// Группы с детализацией — каждый путь на своей строке.
			for _, group := range []string{"alive", "auth_required"} {
				if paths, ok := groups[group]; ok && len(paths) > 0 {
					fmt.Fprintf(&sb, "%s (%d):\n", group, len(paths))
					for _, p := range paths {
						fmt.Fprintf(&sb, "  - %s\n", p)
					}
				}
			}
			// Менее важные группы — агрегированно.
			for _, group := range []string{"server_error", "redirect", "not_found"} {
				if paths, ok := groups[group]; ok && len(paths) > 0 {
					fmt.Fprintf(&sb, "%s (%d): %s\n", group, len(paths), joinTrim(paths, 10))
				}
			}
			sb.WriteString("\n")
		}
	}

	// Извлечённые сущности: emails, technologies, api_paths.
	if v, ok := scan.Get("extracted_content"); ok {
		if ec, ok := v.(ExtractedContent); ok {
			sb.WriteString("== Extracted entities ==\n")
			if len(ec.Technologies) > 0 {
				fmt.Fprintf(&sb, "Technologies: %s\n", strings.Join(ec.Technologies, ", "))
			}
			if len(ec.Emails) > 0 {
				fmt.Fprintf(&sb, "Emails: %s\n", strings.Join(ec.Emails, ", "))
			}
			if len(ec.Versions) > 0 {
				fmt.Fprintf(&sb, "Versions: %s\n", strings.Join(ec.Versions, ", "))
			}
			if len(ec.Names) > 0 {
				fmt.Fprintf(&sb, "Names found: %s\n", strings.Join(ec.Names, ", "))
			}
			if len(ec.Phones) > 0 {
				fmt.Fprintf(&sb, "Phones: %s\n", strings.Join(ec.Phones, ", "))
			}
			sb.WriteString("\n")
		}
	}

	// HTML-структура: формы, generator, structure.
	if v, ok := scan.Get("html_parsed"); ok {
		if hp, ok := v.(HTMLParseResult); ok {
			sb.WriteString("== HTML structure ==\n")
			fmt.Fprintf(&sb, "Forms: %d\n", len(hp.Forms))
			for i, f := range hp.Forms {
				if i >= 5 {
					break
				}
				fmt.Fprintf(&sb, "  - %s form at %s, fields: %s\n",
					f.Type, f.Action, strings.Join(f.Fields, ", "))
			}
			generators := []string{}
			for _, mt := range hp.Metas {
				if mt.Generator != "" {
					generators = append(generators, mt.Generator)
				}
			}
			if len(generators) > 0 {
				fmt.Fprintf(&sb, "Meta generators: %s\n", strings.Join(generators, ", "))
			}
			if len(hp.CommentedEmails) > 0 {
				fmt.Fprintf(&sb, "Emails in comments: %s\n", strings.Join(hp.CommentedEmails, ", "))
			}
			sb.WriteString("\n")
		}
	}

	// DNS / почтовые сервисы.
	if v, ok := scan.Get("mail_services"); ok {
		if ms, ok := v.([]MailService); ok && len(ms) > 0 {
			sb.WriteString("== Mail services ==\n")
			for _, m := range ms {
				fmt.Fprintf(&sb, "  - MX %s (%s)\n", m.MX, m.Provider)
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// --- Утилиты ---

// formatCodes форматирует карту статус-кодов как "200=130, 401=9, 500=12".
func formatCodes(codes map[int]int) string {
	keys := make([]int, 0, len(codes))
	for k := range codes {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d=%d", k, codes[k]))
	}
	return strings.Join(parts, ", ")
}

// topItems возвращает первые N элементов карты по убыванию количества.
func topItems(items map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(items))
	for k, v := range items {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	if len(all) > n {
		all = all[:n]
	}
	parts := make([]string, len(all))
	for i, e := range all {
		parts[i] = fmt.Sprintf("%q", e.k)
	}
	return strings.Join(parts, ", ")
}

// joinTrim соединяет первые N элементов через запятую с многоточием в конце.
func joinTrim(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(", ... (+%d more)", len(items)-n)
}

// truncate обрезает строку до n символов с многоточием.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// structToMap конвертирует структуру в map[string]interface{}
// через JSON-маршалинг. Используется для передачи в html/template,
// чтобы поля были доступны по JSON-именам (с маленькой буквы),
// а не по именам Go-полей (с большой буквы).
//
// Накладные расходы (двойной маршалинг) приемлемы — мы делаем это
// один раз на скан, а не в горячем пути.
func structToMap(v interface{}) map[string]interface{} {
	data, err := json.Marshal(v)
	if err != nil {
		return map[string]interface{}{"error": "marshal failed: " + err.Error()}
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return map[string]interface{}{"error": "unmarshal failed: " + err.Error()}
	}
	return m
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
