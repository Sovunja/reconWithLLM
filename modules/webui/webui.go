package webui

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"recon/core"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// WebUIModule — модуль веб-интерфейса. Реализует core.Module: запускается
// при старте ядра (Init) и держит HTTP-сервер до Shutdown.
//
// В отличие от других модулей, его Run() — пустой: web_ui не участвует
// в pipeline разведки, он живёт параллельно и сам инициирует pipeline
// через ScanManager по запросу пользователя.
type WebUIModule struct {
	addr    string
	manager *core.ScanManager
	server  *http.Server
	tmpl    *template.Template
	// asker — модуль, реализующий core.AIAsker (обычно ai_analyzer).
	// nil если ИИ-модуль не зарегистрирован или не поддерживает Q&A —
	// тогда Q&A эндпоинты возвращают понятную ошибку.
	asker core.AIAsker
}

// New создаёт модуль. manager обязателен — через него UI запускает сканы.
func New(addr string, manager *core.ScanManager) *WebUIModule {
	return &WebUIModule{
		addr:    addr,
		manager: manager,
	}
}

func (m *WebUIModule) Name() string { return "web_ui" }

func (m *WebUIModule) Init(ctx context.Context, kernel *core.Kernel) error {
	// Парсим шаблоны с функциями-помощниками для форматирования в UI.
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"formatTime":     func(t time.Time) string { return t.Format("15:04:05 02.01.2006") },
		"formatDuration": formatDuration,
		"json":           jsonify,
		"hasKey":         hasKey,
	}).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return fmt.Errorf("parse templates: %w", err)
	}
	m.tmpl = tmpl

	// Ищем зарегистрированный модуль, реализующий AIAsker (Q&A интерфейс).
	// Если не нашли — Q&A эндпоинты будут возвращать ошибку 503,
	// но остальная часть UI будет работать как раньше.
	if mod, ok := kernel.Module("ai_analyzer"); ok {
		if asker, ok := mod.(core.AIAsker); ok {
			m.asker = asker
			fmt.Printf("[web_ui] Q&A enabled via ai_analyzer module\n")
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", m.handleIndex)
	mux.HandleFunc("/scans", m.handleScansList)         // HTMX-фрагмент: список сканов
	mux.HandleFunc("/scan/start", m.handleScanStart)    // POST форма запуска
	mux.HandleFunc("/scan/", m.handleScanView)          // /scan/{id}
	mux.HandleFunc("/scan-status/", m.handleScanStatus) // HTMX-фрагмент: статус скана
	mux.HandleFunc("/scan-data/", m.handleScanData)     // HTMX-фрагмент: собранные данные
	mux.HandleFunc("/scan-json/", m.handleScanJSON)     // скачивание JSON-отчёта
	mux.HandleFunc("/scan-ask/", m.handleScanAsk)       // POST: задать вопрос ИИ
	mux.HandleFunc("/scan-history/", m.handleScanHistory) // GET: фрагмент истории Q&A
	mux.Handle("/static/", http.FileServer(http.FS(staticFS)))

	m.server = &http.Server{
		Addr:              m.addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Поднимаем сервер в горутине — Init не должен блокироваться.
	go func() {
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[web_ui] server error: %v\n", err)
		}
	}()
	fmt.Printf("[web_ui] listening on %s\n", m.addr)
	return nil
}

// Run — пустой: модуль не участвует в pipeline.
func (m *WebUIModule) Run(ctx context.Context, scan *core.ScanContext) error { return nil }

func (m *WebUIModule) Shutdown(ctx context.Context) error {
	if m.server == nil {
		return nil
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return m.server.Shutdown(shutdownCtx)
}

// ============================================================
// Обработчики HTTP
// ============================================================

// handleIndex — главная страница с формой запуска и списком сканов.
func (m *WebUIModule) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := struct {
		Scenarios []string
		Scans     []*core.ScanRecord
	}{
		Scenarios: scenarioNames(m.manager.Pipelines()),
		Scans:     m.manager.List(),
	}
	m.render(w, "index.html", data)
}

// handleScansList — HTMX-фрагмент: только таблица сканов, обновляется по таймеру.
func (m *WebUIModule) handleScansList(w http.ResponseWriter, r *http.Request) {
	m.render(w, "scans_list.html", m.manager.List())
}

// handleScanStart принимает форму, запускает скан, перенаправляет на его страницу.
func (m *WebUIModule) handleScanStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	target := r.FormValue("target")
	scenario := r.FormValue("scenario")
	depth, _ := strconv.Atoi(r.FormValue("depth"))
	if depth < 1 {
		depth = 2
	}
	if target == "" || scenario == "" {
		http.Error(w, "target and scenario required", http.StatusBadRequest)
		return
	}

	cfg := map[string]interface{}{
		"hakrawler_depth":   depth,
		"hakrawler_timeout": 60 * time.Second,
		"httpx_timeout":     90 * time.Second,
	}
	rec, err := m.manager.Submit(target, scenario, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// HTMX заголовок для редиректа на страницу скана.
	w.Header().Set("HX-Redirect", "/scan/"+rec.ID)
	w.WriteHeader(http.StatusOK)
}

// handleScanView — страница конкретного скана.
func (m *WebUIModule) handleScanView(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/scan/"):]
	rec, ok := m.manager.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	m.render(w, "scan.html", rec)
}

// handleScanStatus — HTMX-фрагмент: блок статуса. Подгружается каждую секунду.
func (m *WebUIModule) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/scan-status/"):]
	rec, ok := m.manager.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	m.render(w, "scan_status.html", rec)
}

// handleScanData — HTMX-фрагмент: собранные данные. Подгружается после завершения.
func (m *WebUIModule) handleScanData(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/scan-data/"):]
	rec, ok := m.manager.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	m.render(w, "scan_data.html", rec)
}

// handleScanAsk — POST: пользовательский вопрос к ИИ.
// Принимает форму с полем "question", вызывает asker.Ask(),
// сохраняет вопрос и ответ в историю ScanRecord, возвращает
// HTML-фрагмент с обновлённой историей.
func (m *WebUIModule) handleScanAsk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Path[len("/scan-ask/"):]
	rec, ok := m.manager.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if m.asker == nil {
		http.Error(w, "Q&A unavailable: ai_analyzer module not registered",
			http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	question := r.FormValue("question")
	if question == "" {
		http.Error(w, "question is required", http.StatusBadRequest)
		return
	}

	// Сохраняем вопрос ДО вызова LLM — если LLM упадёт или зависнет,
	// у пользователя в UI всё равно отобразится его собственный вопрос.
	rec.AppendMessage("user", question)

	// Используем контекст с длинным таймаутом, потому что инференс
	// 8B модели на 6 ГБ VRAM может занимать до пары минут.
	askCtx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	answer, err := m.asker.Ask(askCtx, rec.Scan(), rec.ChatHistory(), question)
	if err != nil {
		// Сохраняем сообщение об ошибке как ответ ассистента —
		// пользователь увидит причину сбоя в той же ленте диалога.
		rec.AppendMessage("assistant", "Ошибка обращения к LLM: "+err.Error())
	} else {
		rec.AppendMessage("assistant", answer)
	}

	// Возвращаем тот же шаблон что и handleScanHistory — общий фрагмент.
	m.render(w, "scan_history.html", rec)
}

// handleScanHistory — HTMX-фрагмент: текущая история диалога.
// Используется для первоначальной загрузки и опционального обновления.
func (m *WebUIModule) handleScanHistory(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/scan-history/"):]
	rec, ok := m.manager.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	m.render(w, "scan_history.html", rec)
}

// handleScanJSON — отдаёт сырой JSON-отчёт (для скачивания).
func (m *WebUIModule) handleScanJSON(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/scan-json/"):]
	rec, ok := m.manager.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s.json"`, rec.ID))

	report := map[string]interface{}{
		"id":          rec.ID,
		"target":      rec.Target,
		"scenario":    rec.Scenario,
		"status":      rec.Status,
		"started_at":  rec.StartedAt,
		"finished_at": rec.FinishedAt,
		"steps":       rec.Steps,
		"results":     rec.Snapshot(),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report)
}

// ============================================================
// Хелперы
// ============================================================

func (m *WebUIModule) render(w http.ResponseWriter, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := m.tmpl.ExecuteTemplate(w, name, data); err != nil {
		fmt.Printf("[web_ui] render %s: %v\n", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func scenarioNames(p map[string][]string) []string {
	out := make([]string, 0, len(p))
	for k := range p {
		out = append(out, k)
	}
	return out
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
}

func jsonify(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return string(b)
}

func hasKey(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}
	_, ok := m[key]
	return ok
}
