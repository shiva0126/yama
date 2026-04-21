package websocket

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"ad-assessment/shared/types"

	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // restrict in production
	},
}

type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
	rdb        *redis.Client
	logger     *zap.Logger
}

func NewHub(rdb *redis.Client, logger *zap.Logger) *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		rdb:        rdb,
		logger:     logger,
	}
}

func (h *Hub) Run() {
	// Subscribe to Redis channels for events from backend services
	go h.subscribeRedis()

	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			h.logger.Info("WS client connected", zap.Int("total", len(h.clients)))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

func (h *Hub) subscribeRedis() {
	ctx := context.Background()
	sub := h.rdb.Subscribe(ctx,
		types.RedisScanProgressChannel,
		types.RedisAgentStatusChannel,
		types.RedisNewFindingChannel,
	)
	defer sub.Close()

	ch := sub.Channel()
	for msg := range ch {
		var wsMsg types.WSMessage
		switch msg.Channel {
		case types.RedisScanProgressChannel:
			wsMsg.Type = types.WSTypeScanProgress
		case types.RedisAgentStatusChannel:
			wsMsg.Type = types.WSTypeAgentStatus
		case types.RedisNewFindingChannel:
			wsMsg.Type = types.WSTypeNewFinding
		}

		var payload interface{}
		if err := json.Unmarshal([]byte(msg.Payload), &payload); err == nil {
			wsMsg.Payload = payload
			if data, err := json.Marshal(wsMsg); err == nil {
				h.broadcast <- data
			}
		}
	}
}

func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("WS upgrade failed", zap.Error(err))
		return
	}

	client := &Client{hub: h, conn: conn, send: make(chan []byte, 256)}
	h.register <- client

	go client.writePump()
	go client.readPump()
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
