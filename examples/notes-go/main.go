// Command notes-go is a small database-backed app for trying out Nook's
// app databases: a list of notes in PostgreSQL. Run `nook db create
// notes-go` and the app gets DATABASE_URL. It answers "/" with the notes
// and a form, "POST /notes" adds one (signed with the visitor's email from
// the gateway), "/notes.json" lists them as JSON, and "/healthz" answers
// "ok" whether or not the database is reachable (a database outage is
// shown to visitors, it does not restart the app). Without DATABASE_URL
// (the first deploy, before `nook db create`) it says how to add one.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const schema = `CREATE TABLE IF NOT EXISTS notes (
	id         bigserial PRIMARY KEY,
	body       text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 500),
	author     text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now()
)`

type note struct {
	ID        int64     `json:"id"`
	Body      string    `json:"body"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"created_at"`
}

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Notes</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 2rem auto; padding: 0 1rem">
<h1>Notes</h1>
{{if .Error}}<p style="color: #b00">{{.Error}}</p>{{end}}
<form method="post" action="/notes"><input name="body" maxlength="500" required autofocus style="width: 70%">
<button>Add</button></form>
<ul>{{range .Notes}}<li>{{.Body}} <small>({{.Author}}, {{.CreatedAt.Format "2006-01-02 15:04"}})</small></li>{{end}}</ul>
</body></html>`))

type app struct{ db *pgxpool.Pool }

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := &app{}
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		db, err := pgxpool.New(ctx, dsn)
		if err != nil {
			log.Fatalf("database: %v", err)
		}
		defer db.Close()
		a.db = db
		go a.migrate(ctx)
	} else {
		log.Print("DATABASE_URL is not set: run `nook db create notes-go`")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /{$}", a.index)
	mux.HandleFunc("GET /notes.json", a.listJSON)
	mux.HandleFunc("POST /notes", a.add)
	logged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		mux.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
	srv := &http.Server{Addr: ":" + port, Handler: logged, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("notes-go listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// migrate creates the table, retrying while the database is unreachable
// (for example while it is being restored on another node).
func (a *app) migrate(ctx context.Context) {
	for {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := a.db.Exec(c, schema)
		cancel()
		if err == nil {
			log.Print("database ready")
			return
		}
		log.Printf("database not ready yet: %v", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// errNoDatabase means the app has no database yet.
var errNoDatabase = errors.New("this app has no database yet: run `nook db create notes-go`")

func (a *app) notes(ctx context.Context) ([]note, error) {
	if a.db == nil {
		return nil, errNoDatabase
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := a.db.Query(ctx, `SELECT id, body, author, created_at FROM notes ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []note
	for rows.Next() {
		var n note
		if err := rows.Scan(&n.ID, &n.Body, &n.Author, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (a *app) index(w http.ResponseWriter, r *http.Request) {
	notes, err := a.notes(r.Context())
	data := map[string]any{"Notes": notes}
	if err != nil {
		log.Printf("list notes: %v", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		data["Error"] = "The database is unavailable right now; try again shortly."
		if errors.Is(err, errNoDatabase) {
			data["Error"] = "No database yet: run `nook db create notes-go`."
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, data)
}

func (a *app) listJSON(w http.ResponseWriter, r *http.Request) {
	notes, err := a.notes(r.Context())
	if err != nil {
		log.Printf("list notes: %v", err)
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"notes": notes})
}

func (a *app) add(w http.ResponseWriter, r *http.Request) {
	body := strings.TrimSpace(r.FormValue("body"))
	if body == "" || len(body) > 500 {
		http.Error(w, "a note is 1 to 500 characters", http.StatusBadRequest)
		return
	}
	if a.db == nil {
		http.Error(w, errNoDatabase.Error(), http.StatusServiceUnavailable)
		return
	}
	author := r.Header.Get("X-Nook-Email") // set by the gateway; absent for public apps
	if author == "" {
		author = "anonymous"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := a.db.Exec(ctx, `INSERT INTO notes (body, author) VALUES ($1, $2)`, body, author); err != nil {
		log.Printf("add note: %v", err)
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
