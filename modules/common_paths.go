package modules

import (
	"context"
	"log"

	"recon/core"
)

// CommonPathsModule добавляет в ScanContext список типичных
// эндпоинтов для проверки (admin-панели, API, конфиги, и т.д.).
type CommonPathsModule struct{}

func NewCommonPathsModule() *CommonPathsModule { return &CommonPathsModule{} }

func (m *CommonPathsModule) Name() string { return "common_paths" }

func (m *CommonPathsModule) Init(ctx context.Context, kernel *core.Kernel) error {
	return nil
}

// commonPaths — список наиболее частых административных, API и
// диагностических путей. Расширенная версия: ~150 эндпоинтов,
// покрывающих основные категории recon-задач.
var commonPaths = []string{
	// REST API общие префиксы
	"/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/rest/v1",
	"/api/users", "/api/products", "/api/admin", "/api/auth",

	// GraphQL
	"/graphql", "/graphiql", "/playground", "/altair",

	// API-документация
	"/swagger", "/swagger.json", "/swagger.yaml", "/swagger-ui",
	"/swagger-ui.html", "/swagger-ui/index.html",
	"/openapi.json", "/openapi.yaml", "/api-docs", "/api-docs/v1",
	"/docs", "/documentation", "/redoc",

	// Админ-панели
	"/admin", "/admin.php", "/administrator", "/wp-admin", "/wp-login.php",
	"/login", "/login.php", "/signin", "/signup", "/register",
	"/dashboard", "/panel", "/cpanel", "/phpmyadmin", "/pma",
	"/manager", "/manager/html", "/console",

	// Пользовательские области
	"/profile", "/account", "/settings", "/users", "/user",

	// Конфигурация и метаданные
	"/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
	"/.well-known/openid-configuration",
	"/humans.txt", "/crossdomain.xml", "/clientaccesspolicy.xml",

	// Технические эндпоинты
	"/health", "/healthz", "/health-check", "/status", "/ping",
	"/metrics", "/prometheus", "/actuator", "/actuator/health",
	"/actuator/env", "/actuator/info", "/version", "/info", "/debug",

	// Утечки конфигов и исходников (recon-фаза просто фиксирует наличие)
	"/.env", "/.env.local", "/.env.production", "/.env.dev",
	"/.git/config", "/.git/HEAD", "/.gitignore",
	"/.svn/entries", "/.hg/store",
	"/.DS_Store", "/Thumbs.db",
	"/backup", "/backup.zip", "/backup.tar.gz", "/backups",
	"/dump.sql", "/database.sql", "/db.sql",
	"/config", "/config.json", "/config.yml", "/config.yaml",
	"/web.config", "/.htaccess",

	// Серверная диагностика
	"/server-status", "/server-info", "/phpinfo.php", "/info.php",
	"/test.php", "/test.html", "/test", "/debug.php",

	// Cloud / metadata
	"/.aws/credentials", "/instance-data",

	// Логи и временные файлы
	"/log", "/logs", "/error.log", "/access.log",
	"/tmp", "/temp",

	// Файловые ресурсы
	"/uploads", "/upload", "/files", "/file", "/static", "/assets",
	"/media", "/images", "/img",

	// Юридические и контактные страницы (могут содержать email/телефоны)
	"/contact", "/contacts", "/contact-us", "/about", "/about-us",
	"/team", "/staff", "/company", "/people",
	"/privacy", "/privacy-policy", "/terms", "/legal",

	// Juice Shop специфика
	"/ftp", "/encryptionkeys", "/support/logs",
	"/promotion", "/score-board", "/#/score-board",
}

func (m *CommonPathsModule) Run(ctx context.Context, scan *core.ScanContext) error {
	// Берём существующие endpoints (от katana) и добавляем кандидатов.
	// httpx потом отфильтрует мёртвые.
	var existing []Endpoint
	if v, ok := scan.Get("endpoints"); ok {
		if eps, ok := v.([]Endpoint); ok {
			existing = eps
		}
	}

	added := 0
	for _, path := range commonPaths {
		ep := Endpoint{
			URL:    scan.Target + path,
			Method: "GET",
			Source: "wordlist",
			Tag:    "common",
			Tool:   "common_paths",
		}
		existing = append(existing, ep)
		added++
	}

	scan.Set("endpoints", existing)
	log.Printf("[common_paths] added %d candidate paths", added)
	return nil
}

func (m *CommonPathsModule) Shutdown(ctx context.Context) error { return nil }
