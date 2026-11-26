// Command hello-go is a minimal web app for trying out Nook: it answers
// "/" with a greeting (the GREETING environment variable, if set, and the
// visitor's email from the gateway),
// "/healthz" with "ok", and "/env" with the names of the environment
// variables it received (never their values). It logs every request.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		greeting := os.Getenv("GREETING")
		if greeting == "" {
			greeting = "Hello from a Nook app written in Go!"
		}
		_, _ = fmt.Fprintln(w, greeting)
		// The gateway sets X-Nook-Email for signed-in visitors (and strips
		// any value a client sends).
		if email := r.Header.Get("X-Nook-Email"); email != "" {
			_, _ = fmt.Fprintf(w, "Signed in as %s (X-Nook-Email)\n", email)
		}
	})
	mux.HandleFunc("GET /env", func(w http.ResponseWriter, _ *http.Request) {
		names := make([]string, 0)
		for _, kv := range os.Environ() {
			name, _, _ := strings.Cut(kv, "=")
			names = append(names, name)
		}
		sort.Strings(names)
		_, _ = fmt.Fprintln(w, strings.Join(names, "\n"))
	})
	logged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		mux.ServeHTTP(w, r)
	})
	srv := &http.Server{Addr: ":" + port, Handler: logged, ReadHeaderTimeout: 5 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
