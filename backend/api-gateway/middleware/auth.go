package middleware

import (
	"net/http"
	"strings"

	"ad-assessment/api-gateway/handlers"

	"github.com/gin-gonic/gin"
)

func JWTAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
			return
		}

		claims, err := handlers.ParseJWTClaims(parts[1], secret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		username, _ := claims["username"].(string)
		if username == "" {
			username, _ = claims["sub"].(string)
		}
		c.Set("username", username)
		c.Next()
	}
}
