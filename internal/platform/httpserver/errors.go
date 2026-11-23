package httpserver

import (
	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/platform/logging"
)

// ErrorBody is the JSON envelope for every error response, so clients can
// rely on one shape: {"error": {"code": ..., "message": ..., "request_id": ...}}.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail describes one error. Code is a stable machine-readable
// identifier; Message is for humans and may change.
type ErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

// AbortWithError writes the error envelope and stops the handler chain.
func AbortWithError(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, ErrorBody{Error: ErrorDetail{
		Code:      code,
		Message:   message,
		RequestID: logging.RequestIDFromContext(c.Request.Context()),
	}})
}
