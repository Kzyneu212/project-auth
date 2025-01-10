package auth

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// Middleware для проверки JWT-токена
func AuthMiddleware(secretKey string) gin.HandlerFunc {
	// Список маршрутов, для которых пропускается проверка
	allowedPaths := map[string]bool{
		"/":             true,
		"/auth/yandex":  true,
		"/auth/github":  true,
		"/request_code": true,
		"/github/login": true,
	}

	return func(c *gin.Context) {
		// Пропускаем проверку для разрешенных маршрутов
		if allowedPaths[c.FullPath()] {
			c.Next()
			return
		}

		tokenString, err := c.Cookie("Authorization")
		if err != nil {
			log.Println("Отсутствует токен в cookie")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Проверяем алгоритм подписи
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secretKey), nil
		})

		if err != nil {
			log.Printf("Ошибка парсинга токена: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		// Проверяем claims токена
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			email, exists := claims["email"]
			if !exists {
				log.Println("Отсутствует email в claims")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
				c.Abort()
				return
			}
			log.Printf("Токен валиден для email: %s", email)
			c.Set("email", email)
		} else {
			log.Println("Невалидные claims токена")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
			c.Abort()
			return
		}

		c.Next()
	}
}
