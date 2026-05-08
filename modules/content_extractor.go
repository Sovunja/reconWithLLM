package modules

import (
	"context"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"

	"recon/core"
)

// ContentExtractorModule — извлекает структурированные сущности из тел
// ответов через регулярные выражения. Закрывает несколько строк таблицы 1:
//   - Email-адреса
//   - Телефоны (только реальные форматы, не дробные числа из JSON)
//   - Имена сотрудников (HTML meta, JSON-поля, структурированный текст)
//   - Версии ПО (через явные паттерны: package.json, X-Powered-By, JSON-version)
//   - Технологии (через сигнатуры: ng-version, X-Powered-By, классы, etc.)
//   - API-пути в JS
//   - URL и эндпоинты, которые краулер не нашёл
type ContentExtractorModule struct{}

// ExtractedContent — итог работы экстрактора.
type ExtractedContent struct {
	Emails       []string `json:"emails"`
	Phones       []string `json:"phones"`
	Names        []string `json:"names"`
	APIPaths     []string `json:"api_paths"`
	Versions     []string `json:"versions"`
	Technologies []string `json:"technologies"`
	URLs         []string `json:"urls"`
}

func NewContentExtractorModule() *ContentExtractorModule { return &ContentExtractorModule{} }

func (m *ContentExtractorModule) Name() string { return "content_extractor" }

func (m *ContentExtractorModule) Init(ctx context.Context, kernel *core.Kernel) error {
	return nil
}

// ============================================================
// Регексы — все скомпилированы один раз при загрузке пакета.
// ============================================================

var (
	// Email — стандартный паттерн с защитой от ложных срабатываний.
	reEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}`)

	// Телефоны — три ЖЁСТКИХ формата, ничего "распыляющего":
	//   1) международный с +: +7 999 123 4567, +1-555-123-4567
	//   2) US/EU в скобках: (555) 123-4567
	//   3) с префиксом tel:/phone:/callto:
	// Дробные числа из JSON и SVG-координаты не матчатся.
	rePhoneIntl = regexp.MustCompile(`\+\d{1,3}[\s\-]\d{2,4}[\s\-]\d{2,4}[\s\-]\d{2,4}(?:[\s\-]\d{0,4})?`)
	rePhoneUS   = regexp.MustCompile(`\(\d{3}\)\s?\d{3}[\s\-]?\d{4}`)
	rePhoneTel  = regexp.MustCompile(`(?:tel|phone|callto):\+?[\d\s\-()]{7,20}`)

	// Имена — три источника:
	//   1) HTML meta: <meta name="author" content="...">
	//   2) JSON-поле: "author": "X", "fullName": "X", "displayName": "X"
	//   3) Структурированный текст: "Author: John Doe", "by John Doe"
	reAuthorMeta = regexp.MustCompile(`<meta\s+name=["']author["']\s+content=["']([^"']+)["']`)
	reAuthorJSON = regexp.MustCompile(`"(?:author|fullName|displayName|firstName|lastName)"\s*:\s*"([^"]{2,60})"`)
	reAuthorText = regexp.MustCompile(`(?:[Aa]uthor|[Bb]y)\s*[:=]\s*"?([A-ZА-Я][a-zа-я]+\s[A-ZА-Я][a-zа-я]+)"?`)

	// API-пути в JS/HTML: в кавычках любого вида (одинарных/двойных/бектиках).
	reAPIPath = regexp.MustCompile(`["'` + "`" + `](/(?:api|rest|graphql|graphiql|v\d+|admin)(?:/[a-zA-Z0-9/_\-.]*)?)["'` + "`" + `]`)

	// URL в JS/HTML.
	reURL = regexp.MustCompile(`https?://[a-zA-Z0-9.\-]+(?::\d+)?(?:/[a-zA-Z0-9._\-/?=&%~#+]*)?`)
)

// ============================================================
// Технологии — через сигнатуры, а не подстроки.
// "Gin" не должен матчиться в "originally", "Vue" в "value".
// ============================================================

type techMarker struct {
	Tech    string
	Pattern *regexp.Regexp
}

var techMarkers = []techMarker{
	// Frontend frameworks
	{Tech: "Angular", Pattern: regexp.MustCompile(`ng-version|data-ng-|ng-app|@angular/`)},
	{Tech: "React", Pattern: regexp.MustCompile(`react-dom|__REACT_DEVTOOLS|data-reactroot`)},
	{Tech: "Vue.js", Pattern: regexp.MustCompile(`Vue\.config|data-v-[a-f0-9]{8}|__VUE__`)},
	{Tech: "jQuery", Pattern: regexp.MustCompile(`jquery(?:[-.]\d|\.min)|jQuery\.fn\.`)},
	{Tech: "Bootstrap", Pattern: regexp.MustCompile(`bootstrap(?:[-.]\d|\.min)`)},
	{Tech: "Material Design", Pattern: regexp.MustCompile(`mat-(?:button|icon|toolbar|card|form-field)|@angular/material`)},
	{Tech: "RxJS", Pattern: regexp.MustCompile(`\brxjs[/-]|Observable\.subscribe`)},
	{Tech: "Three.js", Pattern: regexp.MustCompile(`\bTHREE\.|three\.js|three\.module`)},

	// Backend
	{Tech: "Express", Pattern: regexp.MustCompile(`X-Powered-By:\s*Express|express/4\.|express\.Router`)},
	{Tech: "Node.js", Pattern: regexp.MustCompile(`Node\.js|nodejs|process\.env\.NODE_ENV`)},
	{Tech: "Django", Pattern: regexp.MustCompile(`csrfmiddlewaretoken|__admin__media|Django/\d`)},
	{Tech: "Flask", Pattern: regexp.MustCompile(`werkzeug|flask\.app|Flask/\d`)},
	{Tech: "nginx", Pattern: regexp.MustCompile(`Server:\s*nginx|nginx/\d`)},
	{Tech: "Apache", Pattern: regexp.MustCompile(`Server:\s*Apache|Apache/\d`)},

	// CMS
	{Tech: "WordPress", Pattern: regexp.MustCompile(`wp-content|wp-includes|/wp-json/`)},
	{Tech: "Drupal", Pattern: regexp.MustCompile(`Drupal\.settings|/sites/default/files/`)},
	{Tech: "Joomla", Pattern: regexp.MustCompile(`/components/com_|Joomla!`)},

	// Build tools / language
	{Tech: "webpack", Pattern: regexp.MustCompile(`webpackJsonp|__webpack_require__|webpack/\d`)},
	{Tech: "TypeScript", Pattern: regexp.MustCompile(`__esModule|tslib_\d|TypeScript`)},
	{Tech: "Babel", Pattern: regexp.MustCompile(`@babel/|_babelHelpers|regeneratorRuntime`)},

	// Database / infra
	{Tech: "MongoDB", Pattern: regexp.MustCompile(`MongoDB|mongodb://|ObjectId\(`)},
	{Tech: "Cloudflare", Pattern: regexp.MustCompile(`__cfduid|cf-ray|cdn-cgi/`)},
}

// ============================================================
// Версии — несколько целевых паттернов вместо общего "слово+цифры".
// ============================================================

var versionPatterns = []*regexp.Regexp{
	// JSON-поле "version": "x.y.z"
	regexp.MustCompile(`"version"\s*:\s*"([^"]{2,30})"`),
	// "Express/4.18.2", "Angular 15.0.4", "Node 18.17.0"
	regexp.MustCompile(`(Express|Angular|Node|nginx|Apache|jQuery|Bootstrap)[/\s]+v?(\d+\.\d+(?:\.\d+)?)`),
	// "@angular/core": "^15.0.0"
	regexp.MustCompile(`@angular/[a-z\-]+["']?\s*:\s*["']?[\^~]?(\d+\.\d+\.\d+)`),
	// Заголовок X-Powered-By
	regexp.MustCompile(`X-Powered-By:\s*([^\r\n]+)`),
}

// ============================================================
// Run
// ============================================================

func (m *ContentExtractorModule) Run(ctx context.Context, scan *core.ScanContext) error {
	v, ok := scan.Get("fetched_responses")
	if !ok {
		log.Printf("[content_extractor] no fetched_responses in context, skipping")
		return nil
	}
	bodies, ok := v.([]FetchedResponse)
	if !ok {
		log.Printf("[content_extractor] fetched_responses has wrong type: %T", v)
		return nil
	}
	log.Printf("[content_extractor] processing %d response bodies", len(bodies))

	emails := newSet()
	phones := newSet()
	names := newSet()
	apiPaths := newSet()
	versions := newSet()
	technologies := newSet()
	urls := newSet()

	for _, body := range bodies {
		if body.BodyPath == "" {
			continue
		}
		raw, err := os.ReadFile(body.BodyPath)
		if err != nil {
			log.Printf("[content_extractor] cannot read %s: %v", body.BodyPath, err)
			continue
		}
		text := string(raw)
		if text == "" {
			continue
		}

		// Определяем тип контента — на JS/CSS не ищем человеческий текст
		// (email/телефоны/имена), только технические маркеры (технологии,
		// API-пути, URL, версии). Это убирает 99% false-positives на
		// минифицированных Angular-чанках.
		ct := strings.ToLower(body.ContentType)
		isHumanReadable := strings.Contains(ct, "html") ||
			strings.Contains(ct, "json") ||
			strings.Contains(ct, "xml") ||
			strings.Contains(ct, "plain") ||
			ct == "" // если тип не указан — пробуем

		// --- Email ---
		// Ищем только в человекочитаемом контенте.
		if isHumanReadable {
			for _, m := range reEmail.FindAllString(text, -1) {
				if isLikelyEmail(m) {
					emails.add(strings.ToLower(m))
				}
			}
		}

		// --- Телефоны ---
		// Только в HTML/JSON — в JS дробные числа дают мусор.
		if isHumanReadable {
			for _, p := range rePhoneIntl.FindAllString(text, -1) {
				phones.add(strings.TrimSpace(p))
			}
			for _, p := range rePhoneUS.FindAllString(text, -1) {
				phones.add(strings.TrimSpace(p))
			}
			for _, match := range rePhoneTel.FindAllString(text, -1) {
				phones.add(strings.TrimSpace(match))
			}
		}

		// --- Имена ---
		// Только в HTML/JSON — JSON-поля типа "fullName" дадут реальные имена.
		if isHumanReadable {
			for _, match := range reAuthorMeta.FindAllStringSubmatch(text, -1) {
				if len(match) > 1 {
					names.add(strings.TrimSpace(match[1]))
				}
			}
			for _, match := range reAuthorJSON.FindAllStringSubmatch(text, -1) {
				if len(match) > 1 && isLikelyName(match[1]) {
					names.add(strings.TrimSpace(match[1]))
				}
			}
			for _, match := range reAuthorText.FindAllStringSubmatch(text, -1) {
				if len(match) > 1 {
					names.add(strings.TrimSpace(match[1]))
				}
			}
		}

		// --- API-пути ---
		// Ищем во всех типах: они часто захардкожены в JS-коде.
		for _, match := range reAPIPath.FindAllStringSubmatch(text, -1) {
			if len(match) > 1 {
				apiPaths.add(match[1])
			}
		}

		// --- Версии ---
		// Ищем во всех типах — версии часто в JSON-файлах и в JS-комментариях.
		for _, pat := range versionPatterns {
			for _, match := range pat.FindAllStringSubmatch(text, -1) {
				if len(match) >= 2 {
					// Берём весь матч целиком — он более информативен.
					versions.add(strings.TrimSpace(match[0]))
				}
			}
		}

		// --- Технологии ---
		for _, marker := range techMarkers {
			if marker.Pattern.MatchString(text) {
				technologies.add(marker.Tech)
			}
		}

		// --- URL ---
		for _, u := range reURL.FindAllString(text, -1) {
			if !strings.Contains(u, "w3.org") && !strings.Contains(u, "schemas.") {
				urls.add(u)
			}
		}
	}

	extracted := ExtractedContent{
		Emails:       emails.list(),
		Phones:       phones.list(),
		Names:        names.list(),
		APIPaths:     apiPaths.list(),
		Versions:     versions.list(),
		Technologies: technologies.list(),
		URLs:         urls.list(),
	}

	log.Printf("[content_extractor] emails=%d phones=%d names=%d api_paths=%d versions=%d tech=%d urls=%d",
		len(extracted.Emails), len(extracted.Phones), len(extracted.Names),
		len(extracted.APIPaths), len(extracted.Versions),
		len(extracted.Technologies), len(extracted.URLs))

	scan.Set("extracted_content", extracted)
	return nil
}

func (m *ContentExtractorModule) Shutdown(ctx context.Context) error { return nil }

// ============================================================
// Хелперы
// ============================================================

type stringSet struct {
	m map[string]struct{}
}

func newSet() *stringSet { return &stringSet{m: map[string]struct{}{}} }
func (s *stringSet) add(v string) {
	if v != "" {
		s.m[v] = struct{}{}
	}
}
func (s *stringSet) list() []string {
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isLikelyEmail отсекает явный мусор: иконки, плейсхолдеры, шаблоны.
func isLikelyEmail(e string) bool {
	low := strings.ToLower(e)
	bad := []string{"example.com", "domain.com", "@2x", "icon", "@font",
		"placeholder", "test@test", "user@host", "a@b.c", ".png", ".jpg", ".svg"}
	for _, b := range bad {
		if strings.Contains(low, b) {
			return false
		}
	}
	return true
}

// isLikelyName отсекает технические значения (UUID, hex-строки, токены),
// которые иногда попадают в JSON-поля типа "displayName".
func isLikelyName(s string) bool {
	if len(s) < 2 || len(s) > 60 {
		return false
	}
	// UUID-формат
	if regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}`).MatchString(s) {
		return false
	}
	// hex-токен
	if regexp.MustCompile(`^[a-fA-F0-9]{20,}$`).MatchString(s) {
		return false
	}
	// Должна быть хотя бы одна буква (не только цифры/символы)
	if !regexp.MustCompile(`[a-zA-ZА-Яа-я]`).MatchString(s) {
		return false
	}
	return true
}
