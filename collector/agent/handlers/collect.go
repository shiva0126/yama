package handlers

import (
	"net/http"

	"ad-assessment/collector-agent/executor"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type Handler struct {
	exec   *executor.Executor
	logger *zap.Logger
}

func New(exec *executor.Executor, logger *zap.Logger) *Handler {
	return &Handler{exec: exec, logger: logger}
}

type CollectRequest struct {
	Domain string `json:"domain" binding:"required"`
}

func (h *Handler) collect(c *gin.Context, taskType string) {
	var req CollectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	scriptName, ok := executor.ModuleMap[taskType]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown task type: " + taskType})
		return
	}

	result, err := h.exec.RunPowerShell(scriptName, req.Domain)
	if err != nil {
		h.logger.Error("collection failed", zap.String("task", taskType), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   err.Error(),
			"task":    taskType,
			"domain":  req.Domain,
		})
		return
	}

	c.JSON(http.StatusOK, result)
}

func (h *Handler) CollectTopology(c *gin.Context)  { h.collect(c, "topology") }
func (h *Handler) CollectUsers(c *gin.Context)     { h.collect(c, "users") }
func (h *Handler) CollectGroups(c *gin.Context)    { h.collect(c, "groups") }
func (h *Handler) CollectComputers(c *gin.Context) { h.collect(c, "computers") }
func (h *Handler) CollectGPOs(c *gin.Context)      { h.collect(c, "gpos") }
func (h *Handler) CollectKerberos(c *gin.Context)  { h.collect(c, "kerberos") }
func (h *Handler) CollectACLs(c *gin.Context)      { h.collect(c, "acls") }
func (h *Handler) CollectDCInfo(c *gin.Context)    { h.collect(c, "dcinfo") }
func (h *Handler) CollectTrusts(c *gin.Context)    { h.collect(c, "trusts") }
func (h *Handler) CollectOUs(c *gin.Context)       { h.collect(c, "ous") }
func (h *Handler) CollectFGPP(c *gin.Context)      { h.collect(c, "fgpp") }
