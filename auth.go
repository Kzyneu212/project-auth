package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var SecretKey string

type Claims struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}

// Получение секретного ключа из переменных окружения
func getSecretKey() []byte {
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		log.Fatal("JWT_SECRET_KEY не установлен")
	}
	return []byte(secretKey)
}

// Функция для создания токена
func CreateToken(email string, roles []string) (string, error) {
	secretKey := getSecretKey() // Получаем секретный ключ при создании токена
	log.Printf("Создание токена для email: %s с ролями: %v", email, roles)

	claims := Claims{
		Email: email,
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "auth-service",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)), // 1 час действия токена
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Подписываем токен с секретным ключом
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		log.Printf("Ошибка при подписании токена: %v", err)
		return "", err
	}

	return tokenString, nil
}

// Функция для проверки и парсинга токена
func ParseToken(tokenString string) (*Claims, error) {
	secretKey := getSecretKey() // Получаем секретный ключ при проверке токена
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok {
		return claims, nil
	} else {
		return nil, err
	}
}

// Реализация авторизации
func HandleYandexCallback(ctx context.Context, code string) (string, error) {

	// 1. Обмен кода на токен доступа
	tokenURL := "https://oauth.yandex.ru/token"
	clientID := os.Getenv("YANDEX_CLIENT_ID")
	clientSecret := os.Getenv("YANDEX_CLIENT_SECRET")

	if clientID == "" || clientSecret == "" {
		log.Println("YANDEX_CLIENT_ID или YANDEX_CLIENT_SECRET не установлены")
		return "", errors.New("missing Yandex credentials")
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	log.Println("Обмен кода на токен доступа. Параметры:", data.Encode())

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		log.Printf("Ошибка обмена кода на токен: %v", err)
		return "", errors.New("failed to exchange code for token")
	}
	defer resp.Body.Close()

	log.Println("Ответ на запрос токена:", resp.Status)

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		log.Printf("Ошибка разбора ответа токена: %v", err)
		return "", errors.New("failed to parse token response")
	}

	log.Printf("Получен токен доступа: %s", tokenResponse.AccessToken)

	// 2. Получение данных пользователя
	userInfoURL := "https://login.yandex.ru/info"
	req, _ := http.NewRequest("GET", userInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)

	client := &http.Client{}
	userInfoResp, err := client.Do(req)
	if err != nil {
		log.Printf("Ошибка запроса данных пользователя: %v", err)
		return "", errors.New("failed to get user info")
	}
	defer userInfoResp.Body.Close()

	log.Println("Ответ на запрос данных пользователя:", userInfoResp.Status)

	// === Логирование полного ответа ===
	body, err := io.ReadAll(userInfoResp.Body)
	if err != nil {
		log.Printf("Ошибка чтения ответа от Яндекса: %v", err)
		return "", errors.New("failed to read user info response")
	}
	log.Printf("Ответ от Яндекса: %s", string(body))

	// === Разбор JSON-ответа ===
	var userInfo struct {
		Email string `json:"default_email"`
	}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		log.Printf("Ошибка разбора данных пользователя: %v", err)
		return "", errors.New("failed to parse user info")
	}

	log.Printf("Получен email пользователя: %s", userInfo.Email)

	// 3. Создание JWT токена
	accessToken, err := CreateToken(userInfo.Email, []string{"student"})
	if err != nil {
		log.Printf("Ошибка создания JWT токена: %v", err)
		return "", errors.New("failed to create JWT token")
	}

	log.Printf("JWT токен успешно создан: %s", accessToken)

	return accessToken, nil
}

// Генерация Refresh Token
func CreateRefreshToken(email string) (string, error) {
	secretKey := getSecretKey() // Получаем секретный ключ при создании refresh токена

	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)), // Действителен 7 дней
		Issuer:    "auth-service",
		Subject:   email,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

// Проверка Refresh Token и генерация новой пары токенов
func RefreshAccessToken(refreshToken string) (string, string, error) {
	secretKey := getSecretKey() // Получаем секретный ключ при проверке refresh токена

	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		return "", "", errors.New("invalid or expired refresh token")
	}

	// Генерируем новую пару токенов
	accessToken, err := CreateToken(claims.Subject, []string{"student"}) // Замените роли на динамические
	if err != nil {
		return "", "", err
	}

	newRefreshToken, err := CreateRefreshToken(claims.Subject)
	if err != nil {
		return "", "", err
	}

	return accessToken, newRefreshToken, nil
}
