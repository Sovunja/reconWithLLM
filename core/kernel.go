package core

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Kernel — ядро системы. Единственная точка управления модулями.
//
// Ответственность ядра:
//   1) Реестр модулей: регистрация и поиск по имени.
//   2) Жизненный цикл: Init/Shutdown всех модулей.
//   3) Pipeline: последовательный запуск модулей по шагам сценария.
//   4) Шина событий: pub/sub-связь между модулями (без прямых вызовов).
//   5) Контроль ошибок и логирование.
//
// Модули НЕ вызывают друг друга напрямую. Все взаимодействия идут через ядро.
type Kernel struct {
	mu          sync.RWMutex
	modules     map[string]Module            // реестр модулей по имени
	subscribers map[string][]EventSubscriber // подписчики по типу события

	eventCh  chan eventEnvelope // канал шины событий
	stopCh   chan struct{}      // сигнал остановки event loop
	loopDone chan struct{}      // подтверждение завершения event loop
	logger   *log.Logger
}

// eventEnvelope — событие вместе с контекстом скана, к которому оно относится.
type eventEnvelope struct {
	event Event
	scan  *ScanContext
}

// NewKernel создаёт новое ядро.
func NewKernel(logger *log.Logger) *Kernel {
	if logger == nil {
		logger = log.Default()
	}
	return &Kernel{
		modules:     make(map[string]Module),
		subscribers: make(map[string][]EventSubscriber),
		eventCh:     make(chan eventEnvelope, 1024),
		stopCh:      make(chan struct{}),
		loopDone:    make(chan struct{}),
		logger:      logger,
	}
}

// Register добавляет модуль в реестр. Вызывается на старте системы
// до Start. Возвращает ошибку, если модуль с таким именем уже есть.
func (k *Kernel) Register(m Module) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	name := m.Name()
	if _, exists := k.modules[name]; exists {
		return fmt.Errorf("module %q is already registered", name)
	}
	k.modules[name] = m

	// Если модуль реализует EventSubscriber — регистрируем его как подписчика.
	if sub, ok := m.(EventSubscriber); ok {
		for _, evType := range sub.Subscriptions() {
			k.subscribers[evType] = append(k.subscribers[evType], sub)
		}
	}

	k.logger.Printf("[kernel] module registered: %s", name)
	return nil
}

// Module возвращает модуль по имени. Используется внутри ядра
// и в тестах. Модули не должны вызывать его напрямую — для них
// взаимодействие идёт через события или через ScanContext.
func (k *Kernel) Module(name string) (Module, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	m, ok := k.modules[name]
	return m, ok
}

// Start инициализирует все зарегистрированные модули и запускает event loop.
// Вызывается один раз при старте системы.
func (k *Kernel) Start(ctx context.Context) error {
	k.mu.RLock()
	mods := make([]Module, 0, len(k.modules))
	for _, m := range k.modules {
		mods = append(mods, m)
	}
	k.mu.RUnlock()

	for _, m := range mods {
		k.logger.Printf("[kernel] init module: %s", m.Name())
		if err := m.Init(ctx, k); err != nil {
			return fmt.Errorf("init %s: %w", m.Name(), err)
		}
	}

	go k.eventLoop(ctx)
	k.logger.Printf("[kernel] started, %d modules ready", len(mods))
	return nil
}

// Stop останавливает event loop и корректно завершает работу всех модулей.
func (k *Kernel) Stop(ctx context.Context) error {
	close(k.stopCh)
	<-k.loopDone

	k.mu.RLock()
	mods := make([]Module, 0, len(k.modules))
	for _, m := range k.modules {
		mods = append(mods, m)
	}
	k.mu.RUnlock()

	var firstErr error
	for _, m := range mods {
		if err := m.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	k.logger.Printf("[kernel] stopped")
	return firstErr
}

// Publish публикует событие в шину. Модули используют этот метод,
// чтобы сообщить ядру о произошедшем (нашли URL, извлекли email,
// ИИ принял решение). Метод неблокирующий: если буфер переполнен —
// событие отбрасывается с предупреждением в логе.
func (k *Kernel) Publish(event Event, scan *ScanContext) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	select {
	case k.eventCh <- eventEnvelope{event: event, scan: scan}:
	default:
		k.logger.Printf("[kernel] event bus full, dropping event %s from %s",
			event.Type, event.Source)
	}
}

// eventLoop — горутина, доставляющая события подписчикам.
func (k *Kernel) eventLoop(ctx context.Context) {
	defer close(k.loopDone)
	for {
		select {
		case <-k.stopCh:
			return
		case <-ctx.Done():
			return
		case env := <-k.eventCh:
			k.dispatch(ctx, env)
		}
	}
}

// dispatch доставляет одно событие всем подписчикам в отдельных горутинах,
// чтобы медленный обработчик не задерживал шину.
func (k *Kernel) dispatch(ctx context.Context, env eventEnvelope) {
	k.mu.RLock()
	subs := append([]EventSubscriber(nil), k.subscribers[env.event.Type]...)
	k.mu.RUnlock()

	for _, sub := range subs {
		go func(s EventSubscriber) {
			if err := s.HandleEvent(ctx, env.event, env.scan); err != nil {
				k.logger.Printf("[kernel] subscriber error on %s: %v",
					env.event.Type, err)
			}
		}(sub)
	}
}

// RunPipeline запускает последовательность модулей для одного скана.
// Список steps — это имена модулей в порядке выполнения. Именно через
// этот метод ядро реализует разные сценарии работы с ИИ:
//
//   Сценарий 1 (ИИ только в анализе):
//     ["crawler", "parser", "ai_analyzer", "reporter", "storage"]
//
//   Сценарий 2 (ИИ ведёт краулинг):
//     ["ai_crawler", "parser", "ai_analyzer", "reporter", "storage"]
//
//   Сценарий 3 (ИИ генерирует гипотезы):
//     ["crawler", "parser", "ai_analyzer", "ai_hypothesis", "reporter", "storage"]
//
// Если какой-то шаг падает с ошибкой — ядро останавливает pipeline.
func (k *Kernel) RunPipeline(ctx context.Context, scan *ScanContext, steps []string) error {
	k.logger.Printf("[kernel] pipeline start: scan=%s scenario=%s steps=%v",
		scan.ID, scan.Scenario, steps)

	var pipelineErr error
	for _, name := range steps {
		m, ok := k.Module(name)
		if !ok {
			pipelineErr = fmt.Errorf("module %q not found in registry", name)
			break
		}

		k.logger.Printf("[kernel] step: %s", name)
		start := time.Now()
		if err := m.Run(ctx, scan); err != nil {
			pipelineErr = fmt.Errorf("step %s failed: %w", name, err)
			k.logger.Printf("[kernel] step %s FAILED in %s: %v",
				name, time.Since(start), err)
			break
		}
		k.logger.Printf("[kernel] step %s done in %s", name, time.Since(start))
	}

	k.logger.Printf("[kernel] pipeline finished: scan=%s err=%v",
		scan.ID, pipelineErr)
	return pipelineErr
}
