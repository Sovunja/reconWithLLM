// Package core содержит ядро системы разведки и базовые контракты,
// через которые ядро взаимодействует с модулями.
package core

import (
	"sync"
	"time"
)

// ScanContext — единый контекст одной задачи разведки.
// Передаётся всем модулям через ядро, накапливая собранные данные
// по мере прохождения этапов pipeline. Доступ потокобезопасный:
// несколько модулей могут писать/читать данные параллельно.
type ScanContext struct {
	ID        string                 // уникальный идентификатор скана
	Target    string                 // целевой URL/домен
	StartedAt time.Time              // время начала разведки
	Scenario  string                 // активный сценарий: "passive_ai", "agentic_ai", "hypothesis_ai"
	Config    map[string]interface{} // параметры запуска (глубина, таймауты и т.д.)

	mu   sync.RWMutex
	data map[string]interface{} // собранные данные между модулями
}

// NewScanContext создаёт новый контекст разведки.
func NewScanContext(id, target, scenario string, cfg map[string]interface{}) *ScanContext {
	return &ScanContext{
		ID:        id,
		Target:    target,
		StartedAt: time.Now(),
		Scenario:  scenario,
		Config:    cfg,
		data:      make(map[string]interface{}),
	}
}

// Set сохраняет произвольные данные в контексте (например, найденные URL,
// извлечённые email, версии ПО). Ключ обычно — имя сущности: "urls", "emails", "tech_stack".
func (c *ScanContext) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = value
}

// Get извлекает данные по ключу. Второй параметр — флаг наличия.
func (c *ScanContext) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.data[key]
	return v, ok
}

// Snapshot возвращает копию всех собранных данных. Используется
// модулем хранения и модулем генерации отчётов в конце pipeline.
func (c *ScanContext) Snapshot() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]interface{}, len(c.data))
	for k, v := range c.data {
		out[k] = v
	}
	return out
}

// Event — сообщение шины событий. Модули не вызывают друг друга напрямую,
// а публикуют события через ядро. Это позволяет, например, краулеру
// сообщить "найден новый URL", а ИИ-аналайзеру подхватить его и решить,
// стоит ли углубляться (Сценарий 2).
type Event struct {
	Type      string      // тип события: "url.found", "email.extracted", "ai.decision.next"
	Source    string      // имя модуля-отправителя
	Payload   interface{} // полезная нагрузка
	Timestamp time.Time
}

// ModuleStatus — статус модуля в жизненном цикле (для логов и отладки).
type ModuleStatus string

const (
	StatusIdle    ModuleStatus = "idle"
	StatusRunning ModuleStatus = "running"
	StatusDone    ModuleStatus = "done"
	StatusFailed  ModuleStatus = "failed"
)
