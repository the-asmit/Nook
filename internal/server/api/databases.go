package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/apperr"
)

// App databases: members see a database; admins and owners create, rotate,
// dump and delete it. Instance admins see the server and move it.

func (h *V1) getDatabase(c *gin.Context) {
	in, err := h.Databases.Get(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, in)
}

func (h *V1) createDatabase(c *gin.Context) {
	in, err := h.Databases.Create(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusAccepted, in)
}

func (h *V1) deleteDatabase(c *gin.Context) {
	ctx := c.Request.Context()
	if err := h.Databases.Delete(ctx, actor(c), c.Param("slug"), c.Param("app")); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	in, err := h.Databases.Get(ctx, actor(c), c.Param("slug"), c.Param("app"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusAccepted, in)
}

func (h *V1) rotateDatabasePassword(c *gin.Context) {
	in, err := h.Databases.RotatePassword(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, in)
}

func (h *V1) createDatabaseDump(c *gin.Context) {
	d, err := h.Databases.CreateDump(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusAccepted, d)
}

func (h *V1) getDatabaseDump(c *gin.Context) {
	id, err := pathUUID(c, "dump")
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	d, err := h.Databases.GetDump(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"), id)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, d)
}

func (h *V1) databaseStatus(c *gin.Context) {
	s, err := h.Databases.Status(c.Request.Context())
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, s)
}

// DatabaseFailoverRequest moves the app database server to a node.
type DatabaseFailoverRequest struct {
	To string `json:"to"`
}

func (h *V1) databaseFailover(c *gin.Context) {
	var req DatabaseFailoverRequest
	if !decodeJSON(c, &req) {
		return
	}
	if req.To == "" || len(req.To) > 63 {
		writeError(c, h.Logger, apperr.Invalid("invalid_body", `"to" (a node name) is required`))
		return
	}
	s, err := h.Databases.Failover(c.Request.Context(), actor(c), req.To)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusAccepted, s)
}

func (h *V1) removeDatabaseServer(c *gin.Context) {
	id, err := pathUUID(c, "server")
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	if err := h.Databases.RemoveServer(c.Request.Context(), actor(c), id); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// NodeLabelsRequest replaces a node's labels.
type NodeLabelsRequest struct {
	Labels map[string]string `json:"labels"`
}

func (h *V1) setNodeLabels(c *gin.Context) {
	var req NodeLabelsRequest
	if !decodeJSON(c, &req) {
		return
	}
	n, err := h.Nodes.SetLabels(c.Request.Context(), actor(c), c.Param("node"), req.Labels)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, nodeView(&n, nil))
}
