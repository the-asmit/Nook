// Command testapp is the app the runtime integration tests deploy (built
// into a one-file image without going through a build). TESTAPP_MODE
// selects its behavior: "serve" (default), "unhealthy" (health check
// answers 500), "exit" (exits at once), "slow" (never listens).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	log.SetFlags(0)
	mode := os.Getenv("TESTAPP_MODE")
	log.Printf("testapp starting: deployment %s, mode %q", os.Getenv("NOOK_DEPLOYMENT"), mode)
	switch mode {
	case "exit":
		log.Print("testapp exits on purpose")
		os.Exit(1)
	case "slow":
		time.Sleep(time.Hour)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if mode == "unhealthy" {
			http.Error(w, "unhealthy on purpose", http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "testapp deployment %s\n", os.Getenv("NOOK_DEPLOYMENT"))
	})
	// /env?k=NAME answers the variable's value (tests check that values,
	// secrets included, reach the container).
	mux.HandleFunc("GET /env", func(w http.ResponseWriter, r *http.Request) {
		v, ok := os.LookupEnv(r.URL.Query().Get("k"))
		if !ok {
			http.Error(w, "unset", http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, v)
	})
	// /fetch?url=... makes a request from inside the container (egress tests).
	mux.HandleFunc("GET /fetch", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL.Query().Get("url"), http.NoBody)
		if err != nil {
			_, _ = fmt.Fprintf(w, "error %v", err)
			return
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			_, _ = fmt.Fprintf(w, "error %v", err)
			return
		}
		_ = resp.Body.Close()
		_, _ = fmt.Fprintf(w, "status %d", resp.StatusCode)
	})
	// /resolve?name=... looks a name up through the container's resolver
	// (DNS egress tests).
	mux.HandleFunc("GET /resolve", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupHost(ctx, r.URL.Query().Get("name"))
		if err != nil {
			_, _ = fmt.Fprintf(w, "error %v", err)
			return
		}
		_, _ = fmt.Fprintf(w, "ok %s", strings.Join(addrs, ","))
	})
	mux.HandleFunc("GET /crash", func(http.ResponseWriter, *http.Request) {
		log.Print("testapp crashes on request")
		os.Exit(3)
	})
	// /write tries to write a file at the path (read-only rootfs tests).
	mux.HandleFunc("GET /write", func(w http.ResponseWriter, r *http.Request) {
		err := os.WriteFile(r.URL.Query().Get("path"), []byte("x"), 0o600)
		_, _ = fmt.Fprint(w, strconv.FormatBool(err == nil))
	})
	// /headers answers the request's host and headers as JSON (gateway
	// tests check what reaches the app).
	mux.HandleFunc("GET /headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"host": r.Host, "headers": r.Header})
	})
	// /sse sends two events, the second after the client's next request
	// to /sse/release (proves the gateway streams instead of buffering).
	release := make(chan struct{}, 1)
	mux.HandleFunc("GET /sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		_ = http.NewResponseController(w).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		case <-time.After(30 * time.Second):
		}
		_, _ = io.WriteString(w, "data: second\n\n")
	})
	mux.HandleFunc("GET /sse/release", func(w http.ResponseWriter, _ *http.Request) {
		select {
		case release <- struct{}{}:
		default:
		}
		_, _ = io.WriteString(w, "released")
	})
	// /ws accepts an upgrade and echoes raw bytes (enough to prove that
	// upgraded connections pass through the gateway).
	mux.HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "upgrade required", http.StatusBadRequest)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, rw)
	})
	logged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("request %s %s", r.Method, r.URL.Path)
		mux.ServeHTTP(w, r)
	})
	srv := &http.Server{Addr: ":" + os.Getenv("PORT"), Handler: logged, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
