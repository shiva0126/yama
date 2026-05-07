package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type SignalPayload struct {
	AgentID string            `json:"agent_id"`
	Source  string            `json:"source"`
	Count   int               `json:"count"`
	Labels  map[string]string `json:"labels"`
}

// ForwardSignal receives a defense signal and forwards it to the signal-collector service.
func (h *Handler) ForwardSignal(c *gin.Context) {
	var payload SignalPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Fill in agent ID from env if not provided
	if payload.AgentID == "" {
		payload.AgentID = os.Getenv("AGENT_ID")
	}
	if payload.Count == 0 {
		payload.Count = 1
	}

	collectorURL := os.Getenv("SIGNAL_COLLECTOR_URL")
	if collectorURL == "" {
		// Best-effort: ack but warn
		h.logger.Warn("SIGNAL_COLLECTOR_URL not set — signal not forwarded")
		c.JSON(http.StatusAccepted, gin.H{
			"status":  "accepted_locally",
			"warning": "SIGNAL_COLLECTOR_URL not configured — signal not forwarded to platform",
			"payload": payload,
		})
		return
	}

	body, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, collectorURL+"/ingest", bytes.NewReader(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("build request: %v", err)})
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.logger.Error("signal forward failed", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("forward failed: %v", err)})
		return
	}
	defer resp.Body.Close()

	h.logger.Info("signal forwarded",
		zap.String("agent_id", payload.AgentID),
		zap.String("source", payload.Source),
		zap.Int("status", resp.StatusCode),
	)

	c.JSON(http.StatusAccepted, gin.H{
		"status":          "forwarded",
		"upstream_status": resp.StatusCode,
		"agent_id":        payload.AgentID,
	})
}
