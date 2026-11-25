package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// sseKeepalive keeps idle proxies from closing a quiet stream.
const sseKeepalive = 15 * time.Second

// startSSE turns the response into a Server-Sent Events stream with
// periodic keepalive comments. write sends one event (safe for concurrent
// use); stop ends the keepalives.
func startSSE(c *gin.Context) (write func(event string, data any) error, stop func()) {
	rc := http.NewResponseController(c.Writer)
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-store")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)

	var mu sync.Mutex
	write = func(event string, data any) error {
		mu.Lock()
		defer mu.Unlock()
		_ = rc.SetWriteDeadline(time.Now().Add(sseKeepalive * 2))
		if event == "" {
			if _, err := fmt.Fprint(c.Writer, ": keepalive\n\n"); err != nil {
				return err
			}
		} else {
			payload, err := json.Marshal(data)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event, payload); err != nil {
				return err
			}
		}
		return rc.Flush()
	}
	done := make(chan struct{})
	if write("", nil) == nil {
		go func() {
			t := time.NewTicker(sseKeepalive)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					if write("", nil) != nil {
						return
					}
				}
			}
		}()
	}
	return write, func() { close(done) }
}
