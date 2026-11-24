package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"uuid"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/platform/httpserver"
)

// statusFor maps a domain error kind to an HTTP status.
func statusFor(k apperr.Kind) int {
	switch k {
	case apperr.KindInvalid:
		return http.StatusBadRequest
	case apperr.KindUnauthenticated:
		return http.StatusUnauthorized
	case apperr.KindForbidden:
		return http.StatusForbidden
	case apperr.KindNotFound:
		return http.StatusNotFound
	case apperr.KindConflict:
		return http.StatusConflict
	case apperr.KindRateLimited:
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}

// writeError responds with the error envelope. Classified errors keep
// their code and message; anything else is logged and reported as a
// generic internal error, so internals never leak to clients.
func writeError(c *gin.Context, logger *slog.Logger, err error) {
	if e, ok := apperr.As(err); ok {
		httpserver.AbortWithError(c, statusFor(e.Kind), e.Code, e.Message)
		return
	}
	logger.ErrorContext(c.Request.Context(), "request failed", "error", err.Error())
	httpserver.AbortWithError(c, http.StatusInternalServerError, "internal", "internal server error")
}

// decodeJSON reads a JSON request body into dst. It requires the JSON
// content type (which also means a cross-site HTML form cannot produce a
// valid request), rejects unknown fields and trailing data, and writes the
// error response itself when it returns false.
func decodeJSON(c *gin.Context, dst any) bool {
	mt, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mt != "application/json" {
		httpserver.AbortWithError(c, http.StatusUnsupportedMediaType, "unsupported_media_type",
			"request body must be application/json")
		return false
	}
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	err = dec.Decode(dst)
	if err == nil {
		if _, extra := dec.Token(); !errors.Is(extra, io.EOF) {
			err = errors.New("unexpected data after the JSON object")
		}
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			httpserver.AbortWithError(c, http.StatusRequestEntityTooLarge, "payload_too_large", "request body is too large")
			return false
		}
		httpserver.AbortWithError(c, http.StatusBadRequest, "invalid_body", "request body is not valid JSON for this endpoint: "+err.Error())
		return false
	}
	return true
}

// Pagination limits.
const (
	defaultPageSize = 50
	maxPageSize     = 100
	maxCursorLength = 512
)

// pageParams reads ?limit= and ?cursor=, decoding the cursor into dst.
func pageParams(c *gin.Context, dst any) (int32, error) {
	limit := defaultPageSize
	if s := c.Query("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxPageSize {
			return 0, apperr.Invalid("invalid_limit", "limit must be between 1 and %d", maxPageSize)
		}
		limit = n
	}
	if s := c.Query("cursor"); s != "" {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if len(s) > maxCursorLength || err != nil || json.Unmarshal(raw, dst) != nil {
			return 0, apperr.Invalid("invalid_cursor", "cursor is not valid; use next_cursor from the previous page")
		}
	}
	return int32(limit), nil
}

// encodeCursor makes an opaque cursor from a position.
func encodeCursor(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// listResponse is the shape of every paginated response.
type listResponse[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// page trims a result fetched with limit+1 rows and sets the next cursor
// from the last returned item.
func page[T, V any](rows []T, limit int32, view func(*T) V, cursor func(*T) any) listResponse[V] {
	resp := listResponse[V]{Items: make([]V, 0, min(len(rows), int(limit)))}
	more := len(rows) > int(limit)
	if more {
		rows = rows[:limit]
	}
	for i := range rows {
		resp.Items = append(resp.Items, view(&rows[i]))
	}
	if more && len(rows) > 0 {
		next := encodeCursor(cursor(&rows[len(rows)-1]))
		resp.NextCursor = &next
	}
	return resp
}

// pathUUID parses a UUID path parameter. A malformed ID cannot name any
// resource, so it is reported as not found.
func pathUUID(c *gin.Context, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Param(name))
	if err != nil {
		return uuid.UUID{}, apperr.NotFound("%s not found", name)
	}
	return id, nil
}
