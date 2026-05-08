package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"recon/core"
)

// StorageModule — модуль хранения результатов разведки.
// Минимальная реализация: дамп всего содержимого ScanContext в JSON-файл.
// В Docker-контейнере /data — это volume, mount-ится на хост в ./data,
// поэтому результат будет доступен с хост-машины после завершения скана.
type StorageModule struct {
	dir string // директория для отчётов
}

func NewStorageModule(dir string) *StorageModule {
	return &StorageModule{dir: dir}
}

func (m *StorageModule) Name() string { return "storage" }

func (m *StorageModule) Init(ctx context.Context, kernel *core.Kernel) error {
	return os.MkdirAll(m.dir, 0o755)
}

func (m *StorageModule) Run(ctx context.Context, scan *core.ScanContext) error {
	// Сохраняем всё, что собрано в контексте, плюс метаданные скана.
	report := map[string]interface{}{
		"scan_id":     scan.ID,
		"target":      scan.Target,
		"scenario":    scan.Scenario,
		"started_at":  scan.StartedAt.Format(time.RFC3339),
		"finished_at": time.Now().Format(time.RFC3339),
		"results":     scan.Snapshot(),
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	path := filepath.Join(m.dir, fmt.Sprintf("scan-%s.json", scan.ID))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	fmt.Printf("[storage] report saved: %s\n", path)
	return nil
}

func (m *StorageModule) Shutdown(ctx context.Context) error { return nil }
