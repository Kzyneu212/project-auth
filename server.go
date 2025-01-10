package main

import (
	"bytes"
	"encoding/json"
	"go-auth/auth"
	"go-auth/database"
	"go-auth/handlers"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

// Хранилище тестов в памяти (для упрощения)
var testStorage []struct {
	Name      string   `json:"name"`
	Questions []string `json:"questions"`
}
var testMutex sync.Mutex // Для потокобезопасности

func main() {
	// Загрузка переменных из .env файла
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Ошибка загрузки .env файла: %v", err)
	}

	// Загружаем секретный ключ
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		log.Fatal("JWT_SECRET_KEY не установлен")
	}
	log.Println("Loaded JWT_SECRET_KEY:", secretKey)

	// Передаем секретный ключ в auth.SecretKey
	auth.SecretKey = secretKey

	// Инициализация MongoDB
	mongoURI := os.Getenv("MONGO_URI")
	err = database.InitMongoDB(mongoURI)
	if err != nil {
		log.Printf("Ошибка подключения к MongoDB: %v. Приложение продолжит работу без подключения к базе данных.", err)
	}

	// Инициализация Redis
	err = auth.InitRedis()
	if err != nil {
		log.Printf("Ошибка подключения к Redis: %v. Приложение продолжит работу без подключения к Redis.", err)
	}

	// Инициализация Gin
	r := gin.Default()

	// Загружаем шаблоны из папки templates
	r.LoadHTMLGlob("../templates/*")

	// Добавляем маршруты
	r.GET("/", handlers.IndexHandler)
	r.GET("/auth/yandex", handlers.YandexAuthHandler)
	r.GET("/auth/github", handlers.GithubAuthHandler)
	r.GET("/login", handlers.LoginHandler)
	r.GET("/yandex/login", handlers.YandexLoginHandler)
	r.GET("/yandex/callback", handlers.YandexCallbackHandler)
	r.GET("/github/login", handlers.GitHubLoginHandler)
	r.GET("/github/callback", handlers.GitHubCallbackHandler)
	r.POST("/verify_code", handlers.VerifyCodeHandler)
	r.GET("/request_code", handlers.RequestCodeForm)
	r.POST("/request_code", handlers.RequestCodeHandler)
	r.Static("/static", "./static")

	r.GET("/profile", handlers.ProfileHandler)

	// Приватные маршруты
	r.GET("/protected", handlers.ProtectedHandler)

	// Обработчик для получения списка тестов
	r.GET("/api/tests", func(c *gin.Context) {
		testMutex.Lock()
		defer testMutex.Unlock()

		// Форматируем ответ для клиента
		formattedTests := make([]map[string]interface{}, len(testStorage))
		for i, test := range testStorage {
			formattedTests[i] = map[string]interface{}{
				"testName":  test.Name,
				"questions": test.Questions,
			}
		}

		c.JSON(http.StatusOK, formattedTests)
	})

	//Интеграция Главного Модуля
	// Страница создания теста
	r.GET("/create_test", func(c *gin.Context) {
		c.HTML(http.StatusOK, "create_test.html", nil)
	})

	// API для создания тестов
	r.POST("/api/tests", func(c *gin.Context) {
		var test struct {
			Name      string   `json:"name"`
			Questions []string `json:"questions"`
		}

		if err := c.ShouldBindJSON(&test); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// Конвертируем данные теста в JSON для передачи в C++-модуль
		testData, err := json.Marshal(test)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process test data"})
			return
		}

		// Запуск C++-бинарника и передача данных через stdin
		cmd := exec.Command("../../MainModule/main") // Укажите путь к бинарнику
		cmd.Stdin = bytes.NewReader(testData)        // Передача JSON-данных через stdin

		// Получение вывода от C++-модуля
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Ошибка выполнения C++-модуля: %v, Output: %s", err, string(output))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process test with C++ module", "details": string(output)})
			return
		}

		log.Println("C++ module output:", string(output))
		c.JSON(http.StatusOK, gin.H{"message": "Test processed successfully", "cpp_output": string(output)})
	})

	log.Println("REDIS_ADDR:", os.Getenv("REDIS_ADDR"))

	// Запуск сервера
	r.Run(":8080")
}
