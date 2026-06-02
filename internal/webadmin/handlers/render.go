package handlers

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"sync"
)

//go:embed templates
var templateFS embed.FS

// PageData holds common data passed to every page template.
type PageData struct {
	Username  string
	CSRFToken string
	Flash     string
	FlashType string // "success" or "error"
	Data      any
}

// Renderer parses and caches templates.
type Renderer struct {
	mu    sync.RWMutex
	cache map[string]*template.Template
	funcs template.FuncMap
}

// NewRenderer creates a template renderer.
func NewRenderer() *Renderer {
	return &Renderer{
		cache: make(map[string]*template.Template),
		funcs: template.FuncMap{
			"humanBytes": humanBytes,
		},
	}
}

// Render executes the named page template into the response writer.
// The page template is combined with the base layout and partials.
func (r *Renderer) Render(w http.ResponseWriter, page string, data PageData) error {
	tmpl, err := r.getTemplate(page)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return tmpl.ExecuteTemplate(w, "base", data)
}

// RenderPartial executes a named partial template (no base layout).
func (r *Renderer) RenderPartial(w io.Writer, name string, data any) error {
	tmpl, err := r.getPartials()
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, name, data)
}

func (r *Renderer) getTemplate(page string) (*template.Template, error) {
	r.mu.RLock()
	tmpl, ok := r.cache[page]
	r.mu.RUnlock()
	if ok {
		return tmpl, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double check after acquiring write lock
	if tmpl, ok := r.cache[page]; ok {
		return tmpl, nil
	}

	tmpl, err := template.New("").Funcs(r.funcs).ParseFS(templateFS,
		"templates/base.html",
		"templates/partials.html",
		fmt.Sprintf("templates/%s.html", page),
	)
	if err != nil {
		return nil, fmt.Errorf("parse template %s: %w", page, err)
	}
	r.cache[page] = tmpl
	return tmpl, nil
}

func (r *Renderer) getPartials() (*template.Template, error) {
	const key = "_partials"
	r.mu.RLock()
	tmpl, ok := r.cache[key]
	r.mu.RUnlock()
	if ok {
		return tmpl, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if tmpl, ok := r.cache[key]; ok {
		return tmpl, nil
	}

	tmpl, err := template.New("").Funcs(r.funcs).ParseFS(templateFS, "templates/partials.html")
	if err != nil {
		return nil, fmt.Errorf("parse partials: %w", err)
	}
	r.cache[key] = tmpl
	return tmpl, nil
}

// humanBytes formats a byte count into a human-readable string.
func humanBytes(b int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
