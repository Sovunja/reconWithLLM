package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"recon/core"
	"recon/internal/execrunner"
)

// SubfinderModule — адаптер для ProjectDiscovery subfinder.
// Не изобретает велосипед: запускает внешний бинарник через execrunner
// и нормализует его NDJSON-вывод в единую модель Subdomain.
type SubfinderModule struct {
	kernel *core.Kernel
}

// Subdomain — нормализованная сущность. Все модули-адаптеры приводят
// свой вывод к единым моделям, чтобы ИИ и отчёты работали с одной схемой.
type Subdomain struct {
	Name   string `json:"name"`
	Source string `json:"source"` // источник, нашедший поддомен (passive DB)
	Tool   string `json:"tool"`   // инструмент-сборщик
}

func NewSubfinderModule() *SubfinderModule { return &SubfinderModule{} }

func (m *SubfinderModule) Name() string { return "subfinder" }

// Init проверяет наличие бинарника на старте, чтобы провалить инициализацию
// раньше, чем пользователь запустит скан и получит ошибку посреди работы.
func (m *SubfinderModule) Init(ctx context.Context, kernel *core.Kernel) error {
	m.kernel = kernel
	if _, err := exec.LookPath("subfinder"); err != nil {
		return fmt.Errorf("subfinder binary not found in PATH: %w", err)
	}
	return nil
}

func (m *SubfinderModule) Run(ctx context.Context, scan *core.ScanContext) error {
	// Параметры из ScanContext.Config — для гибкой настройки через web_ui.
	timeout := 5 * time.Minute
	if t, ok := scan.Config["subfinder_timeout"].(time.Duration); ok {
		timeout = t
	}

	var subdomains []Subdomain

	// Колбэк на каждую строку NDJSON: парсим, нормализуем, публикуем событие.
	onLine := func(line []byte) {
		var raw struct {
			Host   string `json:"host"`
			Source string `json:"source"`
		}
		if err := json.Unmarshal(line, &raw); err != nil {
			return // битая строка — пропускаем, не валим скан
		}
		sd := Subdomain{Name: raw.Host, Source: raw.Source, Tool: "subfinder"}
		subdomains = append(subdomains, sd)

		// Публикуем событие — httpx подхватит и сразу проверит живучесть хоста.
		m.kernel.Publish(core.Event{
			Type:    "subdomain.found",
			Source:  m.Name(),
			Payload: sd,
		}, scan)
	}

	res, err := execrunner.Run(ctx, execrunner.Spec{
		Bin: "subfinder",
		Args: []string{
			"-d", scan.Target,
			"-silent",        // без баннеров и прогресса
			"-oJ",            // NDJSON в stdout
			"-all",           // все источники (~30 пассивных DB)
			"-timeout", "30", // таймаут на отдельный источник
		},
		Timeout: timeout,
		OnLine:  onLine,
	})
	if err != nil {
		// Если процесс был отменён — это не ошибка модуля, а штатное прерывание.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("subfinder failed (exit=%d, stderr=%q): %w",
			res.ExitCode, string(res.Stderr), err)
	}

	scan.Set("subdomains", subdomains)
	return nil
}

func (m *SubfinderModule) Shutdown(ctx context.Context) error { return nil }
