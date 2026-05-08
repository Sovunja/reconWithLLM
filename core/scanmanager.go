package core

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ScanStatus — статус скана для UI.
type ScanStatus string

const (
	ScanStatusPending  ScanStatus = "pending"  // создан, ещё не запущен
	ScanStatusRunning  ScanStatus = "running"  // pipeline выполняется
	ScanStatusDone     ScanStatus = "done"     // pipeline успешно завершён
	ScanStatusFailed   ScanStatus = "failed"   // pipeline упал с ошибкой
)

// ScanRecord — метаданные одного скана для UI.
// В отличие от ScanContext (который про данные), ScanRecord — про процесс:
// статус, текущий шаг, время выполнения, ошибки.
type ScanRecord struct {
	ID          string     `json:"id"`
	Target      string     `json:"target"`
	Scenario    string     `json:"scenario"`
	Status      ScanStatus `json:"status"`
	CurrentStep string     `json:"current_step,omitempty"`
	Steps       []string   `json:"steps"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	Error       string     `json:"error,omitempty"`

	// scan хранится в памяти на время работы; после завершения остаётся
	// доступен через storage. UI читает либо отсюда (если scan активен),
	// либо из storage (если уже завершён).
	scan *ScanContext

	// chatHistory — история диалога Q&A для Сценария 1 (passive_ai).
	// Каждый скан имеет независимый контекст беседы. Защищаем мьютексом
	// потому что UI может читать историю параллельно с её обновлением.
	chatMu      sync.Mutex
	chatHistory []ChatMessage
}

// ChatMessage — одно сообщение в Q&A диалоге.
type ChatMessage struct {
	Role      string    `json:"role"`      // "user" или "assistant"
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

// AppendMessage атомарно добавляет сообщение в историю диалога.
func (r *ScanRecord) AppendMessage(role, content string) {
	r.chatMu.Lock()
	defer r.chatMu.Unlock()
	r.chatHistory = append(r.chatHistory, ChatMessage{
		Role:      role,
		Content:   content,
		Timestamp: time.Now(),
	})
}

// ChatHistory возвращает копию истории диалога. Безопасно для конкурентного
// чтения: возвращается новый слайс, исходный остаётся нетронутым.
func (r *ScanRecord) ChatHistory() []ChatMessage {
	r.chatMu.Lock()
	defer r.chatMu.Unlock()
	out := make([]ChatMessage, len(r.chatHistory))
	copy(out, r.chatHistory)
	return out
}

// Scan даёт публичный доступ к ScanContext. Нужен модулю анализа,
// чтобы в Q&A собрать контекст из собранных данных.
func (r *ScanRecord) Scan() *ScanContext {
	return r.scan
}

// Duration возвращает длительность скана. Удобно для шаблонов.
func (r *ScanRecord) Duration() time.Duration {
	end := time.Now()
	if r.FinishedAt != nil {
		end = *r.FinishedAt
	}
	return end.Sub(r.StartedAt)
}

// Snapshot возвращает собранные данные скана (если они ещё доступны в памяти).
func (r *ScanRecord) Snapshot() map[string]interface{} {
	if r.scan == nil {
		return nil
	}
	return r.scan.Snapshot()
}

// ScanManager оркестрирует асинхронный запуск сканов.
// Это связующее звено между HTTP-обработчиками (которые принимают запрос)
// и ядром (которое выполняет pipeline).
type ScanManager struct {
	kernel    *Kernel
	pipelines map[string][]string // сценарий -> список шагов

	mu      sync.RWMutex
	records map[string]*ScanRecord // все скана в памяти, ключ = ID
}

// NewScanManager создаёт менеджер.
// pipelines — карта сценариев в наборы шагов pipeline (как в main.go).
func NewScanManager(k *Kernel, pipelines map[string][]string) *ScanManager {
	return &ScanManager{
		kernel:    k,
		pipelines: pipelines,
		records:   make(map[string]*ScanRecord),
	}
}

// Submit регистрирует новый скан и асинхронно запускает его pipeline.
// Возвращает ScanRecord — UI может сразу показать его в списке со статусом "running".
func (sm *ScanManager) Submit(target, scenario string, cfg map[string]interface{}) (*ScanRecord, error) {
	steps, ok := sm.pipelines[scenario]
	if !ok {
		return nil, fmt.Errorf("unknown scenario: %s", scenario)
	}

	id := fmt.Sprintf("scan-%d", time.Now().UnixNano())
	scan := NewScanContext(id, target, scenario, cfg)

	rec := &ScanRecord{
		ID:        id,
		Target:    target,
		Scenario:  scenario,
		Status:    ScanStatusRunning,
		Steps:     steps,
		StartedAt: time.Now(),
		scan:      scan,
	}

	sm.mu.Lock()
	sm.records[id] = rec
	sm.mu.Unlock()

	// Запускаем pipeline в отдельной горутине. UI не ждёт.
	go sm.run(rec)

	return rec, nil
}

// run выполняет pipeline и обновляет запись по мере прохождения шагов.
// Обновление CurrentStep делаем через прокси-логирование: ядро сейчас
// логирует шаги в stdout, мы дублируем эту логику здесь.
func (sm *ScanManager) run(rec *ScanRecord) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Прогон шагов вручную (а не через kernel.RunPipeline), чтобы между
	// шагами обновлять CurrentStep — это нужно для прогресса в UI.
	var pipelineErr error
	for _, name := range rec.Steps {
		sm.mu.Lock()
		rec.CurrentStep = name
		sm.mu.Unlock()

		m, ok := sm.kernel.Module(name)
		if !ok {
			pipelineErr = fmt.Errorf("module %q not found", name)
			break
		}
		if err := m.Run(ctx, rec.scan); err != nil {
			pipelineErr = fmt.Errorf("step %s: %w", name, err)
			break
		}
	}

	finished := time.Now()
	sm.mu.Lock()
	rec.FinishedAt = &finished
	rec.CurrentStep = ""
	if pipelineErr != nil {
		rec.Status = ScanStatusFailed
		rec.Error = pipelineErr.Error()
	} else {
		rec.Status = ScanStatusDone
	}
	sm.mu.Unlock()
}

// Get возвращает запись скана по ID.
func (sm *ScanManager) Get(id string) (*ScanRecord, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	r, ok := sm.records[id]
	return r, ok
}

// List возвращает все записи, отсортированные по времени старта (новые первыми).
func (sm *ScanManager) List() []*ScanRecord {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	out := make([]*ScanRecord, 0, len(sm.records))
	for _, r := range sm.records {
		out = append(out, r)
	}
	// Сортировка пузырьком — у нас редко больше 20 сканов в UI.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].StartedAt.After(out[i].StartedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// Pipelines возвращает зарегистрированные сценарии — для отрисовки в форме.
func (sm *ScanManager) Pipelines() map[string][]string {
	return sm.pipelines
}
