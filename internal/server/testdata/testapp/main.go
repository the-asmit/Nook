// Command testapp is the app the runtime integration tests deploy (built
// into a one-file image without going through a build). TESTAPP_MODE
// selects its behavior: "serve" (default), "unhealthy" (health check
// answers 500), "exit" (exits at once), "slow" (never listens).
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
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
	mux.HandleFunc("GET /crash", func(http.ResponseWriter, *http.Request) {
		log.Print("testapp crashes on request")
		os.Exit(3)
	})
	// /write tries to write a file at the path (read-only rootfs tests).
	mux.HandleFunc("GET /write", func(w http.ResponseWriter, r *http.Request) {
		err := os.WriteFile(r.URL.Query().Get("path"), []byte("x"), 0o600)
		_, _ = fmt.Fprint(w, strconv.FormatBool(err == nil))
	})
	logged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("request %s %s", r.Method, r.URL.Path)
		mux.ServeHTTP(w, r)
	})
	srv := &http.Server{Addr: ":" + os.Getenv("PORT"), Handler: logged, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
