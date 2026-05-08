package modules

import (
	"context"
	"log"
	"os"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"recon/core"
)

// HTMLParserModule — структурный парсинг HTML-тел.
// В отличие от content_extractor (регекспы по сырому тексту),
// этот модуль строит DOM-дерево и проходит по нему семантически.
//
// Закрывает несколько строк таблицы 1:
//   - Login-формы и формы регистрации (теги <form>, <input>)
//   - Версии CMS (через <meta name="generator">)
//   - Email из HTML-комментариев
//   - Структура компании (поиск ссылок /about, /team, /contacts)
type HTMLParserModule struct{}

// FormInfo — описание найденной формы.
type FormInfo struct {
	URL    string   `json:"url"`           // страница, на которой найдена форма
	Action string   `json:"action"`        // action= формы (куда отправляется)
	Method string   `json:"method"`        // GET, POST
	Type   string   `json:"type"`          // login, signup, search, other
	Fields []string `json:"fields"`        // имена input-полей
}

// MetaInfo — собранные мета-теги.
type MetaInfo struct {
	URL       string `json:"url"`
	Generator string `json:"generator,omitempty"`   // CMS!
	Author    string `json:"author,omitempty"`
	Description string `json:"description,omitempty"`
	Keywords  string `json:"keywords,omitempty"`
}

// CompanyStructure — найденные страницы из «структуры компании».
type CompanyStructure struct {
	About    []string `json:"about,omitempty"`     // ссылки на /about, /о-нас и т.п.
	Team     []string `json:"team,omitempty"`      // /team, /сотрудники
	Contacts []string `json:"contacts,omitempty"`  // /contacts, /связаться
	Careers  []string `json:"careers,omitempty"`   // /careers, /jobs, /вакансии
	Privacy  []string `json:"privacy,omitempty"`   // /privacy, /политика
}

// HTMLParseResult — итоговый результат всего HTML-парсинга.
type HTMLParseResult struct {
	Forms             []FormInfo       `json:"forms"`
	Metas             []MetaInfo       `json:"metas"`
	CompanyStructure  CompanyStructure `json:"company_structure"`
	CommentedEmails   []string         `json:"commented_emails"` // email из HTML-комментариев
	Comments          []string         `json:"comments"`         // сами комментарии (полезные)
}

func NewHTMLParserModule() *HTMLParserModule { return &HTMLParserModule{} }

func (m *HTMLParserModule) Name() string { return "html_parser" }

func (m *HTMLParserModule) Init(ctx context.Context, kernel *core.Kernel) error {
	return nil
}

// Шаблоны для классификации ссылок в структуре компании.
// На русском и английском, чтобы работать на корпоративных сайтах разных регионов.
var structureKeywords = map[string][]string{
	"about":    {"about", "company", "о-нас", "о_нас", "о-компании", "обо-нас"},
	"team":     {"team", "staff", "people", "employees", "сотрудники", "команда", "наша-команда"},
	"contacts": {"contact", "contacts", "связатьс", "контакт"},
	"careers":  {"career", "careers", "jobs", "vacancy", "vacancies", "вакансии", "карьера"},
	"privacy":  {"privacy", "policy", "политик", "конфиденциальн"},
}

// Регекс для email из комментариев (не такой строгий, как в content_extractor —
// здесь мы уже знаем, что это HTML-комментарий, false-positives меньше).
var reCommentEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

func (m *HTMLParserModule) Run(ctx context.Context, scan *core.ScanContext) error {
	v, ok := scan.Get("fetched_responses")
	if !ok {
		log.Printf("[html_parser] no fetched_responses in context, skipping")
		return nil
	}
	bodies, ok := v.([]FetchedResponse)
	if !ok {
		log.Printf("[html_parser] fetched_responses has wrong type: %T", v)
		return nil
	}

	result := HTMLParseResult{
		Forms:           []FormInfo{},
		Metas:           []MetaInfo{},
		CompanyStructure: CompanyStructure{},
		CommentedEmails: []string{},
		Comments:        []string{},
	}
	emailSet := newSet()
	commentSet := newSet()

	processed := 0
	for _, body := range bodies {
		// Парсим только HTML — для JSON/JS у нас content_extractor.
		ct := strings.ToLower(body.ContentType)
		if !strings.Contains(ct, "html") {
			continue
		}
		if body.BodyPath == "" {
			continue
		}
		raw, err := os.ReadFile(body.BodyPath)
		if err != nil {
			log.Printf("[html_parser] cannot read %s: %v", body.BodyPath, err)
			continue
		}

		doc, err := html.Parse(strings.NewReader(string(raw)))
		if err != nil {
			log.Printf("[html_parser] cannot parse HTML %s: %v", body.URL, err)
			continue
		}

		// Один проход по DOM — собираем всё за раз.
		m.walk(doc, body.URL, &result, emailSet, commentSet)
		processed++
	}

	result.CommentedEmails = emailSet.list()
	result.Comments = commentSet.list()

	log.Printf("[html_parser] processed=%d forms=%d metas=%d emails=%d",
		processed, len(result.Forms), len(result.Metas), len(result.CommentedEmails))

	scan.Set("html_parsed", result)
	return nil
}

func (m *HTMLParserModule) Shutdown(ctx context.Context) error { return nil }

// walk рекурсивно обходит DOM и заполняет result.
func (m *HTMLParserModule) walk(n *html.Node, sourceURL string, result *HTMLParseResult,
	emails, comments *stringSet) {

	if n == nil {
		return
	}

	switch n.Type {
	case html.CommentNode:
		// HTML-комментарий: ищем email и сохраняем содержимое если оно похоже на полезное.
		text := n.Data
		for _, e := range reCommentEmail.FindAllString(text, -1) {
			if isLikelyEmail(e) {
				emails.add(strings.ToLower(e))
			}
		}
		// Полезный комментарий — это что-то длиннее 10 символов и не служебный.
		clean := strings.TrimSpace(text)
		if len(clean) > 10 && len(clean) < 500 && !isBoilerplateComment(clean) {
			comments.add(clean)
		}

	case html.ElementNode:
		switch n.Data {
		case "form":
			form := parseForm(n, sourceURL)
			result.Forms = append(result.Forms, form)
			// Не идём вглубь формы — input-поля уже собраны parseForm.
			return

		case "meta":
			meta := parseMeta(n, sourceURL)
			if meta.Generator != "" || meta.Author != "" {
				result.Metas = append(result.Metas, meta)
			}

		case "a":
			// Анализируем ссылки на структуру компании.
			href := getAttr(n, "href")
			if href == "" {
				break
			}
			classify(href, &result.CompanyStructure)
		}
	}

	// Рекурсия по детям.
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		m.walk(c, sourceURL, result, emails, comments)
	}
}

// parseForm собирает информацию о форме — поля, action, тип.
func parseForm(formNode *html.Node, sourceURL string) FormInfo {
	form := FormInfo{
		URL:    sourceURL,
		Action: getAttr(formNode, "action"),
		Method: strings.ToUpper(getAttr(formNode, "method")),
		Fields: []string{},
	}
	if form.Method == "" {
		form.Method = "GET"
	}

	// Собираем имена input-полей.
	collectInputs(formNode, &form.Fields)

	// Классифицируем форму по полям.
	form.Type = classifyForm(form.Fields, form.Action)
	return form
}

// collectInputs рекурсивно собирает имена <input>, <textarea>, <select>.
func collectInputs(n *html.Node, fields *[]string) {
	if n.Type == html.ElementNode {
		switch n.Data {
		case "input", "textarea", "select":
			name := getAttr(n, "name")
			if name == "" {
				name = getAttr(n, "id")
			}
			if name != "" {
				*fields = append(*fields, name)
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		collectInputs(c, fields)
	}
}

// classifyForm определяет тип формы по составу полей.
func classifyForm(fields []string, action string) string {
	hasField := func(needle string) bool {
		needle = strings.ToLower(needle)
		for _, f := range fields {
			if strings.Contains(strings.ToLower(f), needle) {
				return true
			}
		}
		return false
	}
	low := strings.ToLower(action)

	hasPassword := hasField("password") || hasField("pass") || hasField("pwd")
	hasUser := hasField("user") || hasField("login") || hasField("email")
	hasNew := hasField("confirm") || hasField("repeat") || hasField("name") ||
		strings.Contains(low, "register") || strings.Contains(low, "signup")
	hasSearch := hasField("search") || hasField("query") || hasField("q")

	switch {
	case hasPassword && hasNew:
		return "signup"
	case hasPassword && hasUser:
		return "login"
	case hasPassword:
		return "auth"
	case hasSearch:
		return "search"
	}
	return "other"
}

// parseMeta собирает важные мета-теги.
func parseMeta(metaNode *html.Node, sourceURL string) MetaInfo {
	name := strings.ToLower(getAttr(metaNode, "name"))
	content := getAttr(metaNode, "content")
	out := MetaInfo{URL: sourceURL}
	switch name {
	case "generator":
		out.Generator = content // тут может быть "WordPress 6.4.2", "Drupal 10" и т.д.
	case "author":
		out.Author = content
	case "description":
		out.Description = content
	case "keywords":
		out.Keywords = content
	}
	return out
}

// classify определяет, к какой категории структуры относится ссылка.
func classify(href string, s *CompanyStructure) {
	low := strings.ToLower(href)
	for category, kws := range structureKeywords {
		for _, kw := range kws {
			if !strings.Contains(low, kw) {
				continue
			}
			switch category {
			case "about":
				s.About = appendUnique(s.About, href)
			case "team":
				s.Team = appendUnique(s.Team, href)
			case "contacts":
				s.Contacts = appendUnique(s.Contacts, href)
			case "careers":
				s.Careers = appendUnique(s.Careers, href)
			case "privacy":
				s.Privacy = appendUnique(s.Privacy, href)
			}
			return
		}
	}
}

// appendUnique добавляет в слайс если такого ещё нет.
func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// getAttr вытаскивает значение атрибута по имени.
func getAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// isBoilerplateComment отсекает условные комментарии IE,
// шаблонные подсказки и прочий шум.
func isBoilerplateComment(s string) bool {
	low := strings.ToLower(s)
	for _, marker := range []string{
		"[if ", "<![endif]",       // условные комментарии IE
		"google tag manager",
		"yandex.metrika",
		"facebook pixel",
		"end of",
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}
