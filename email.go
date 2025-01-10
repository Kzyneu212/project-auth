package auth

import (
	//"crypto/tls"
	"fmt"
	"net/smtp"
	"os"
)

// Отправка email
func SendEmail(recipient, code string) error {
	from := os.Getenv("SMTP_USERNAME")
	password := os.Getenv("SMTP_PASSWORD")
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	addr := fmt.Sprintf("%s:%s", host, port)

	// Сообщение
	msg := []byte(fmt.Sprintf("Subject: Verification Code\n\nYour code is: %s", code))
	auth := smtp.PlainAuth("", from, password, host)

	// Отправка
	err := smtp.SendMail(addr, auth, from, []string{recipient}, msg)
	if err != nil {
		return fmt.Errorf("ошибка отправки email: %v", err)
	}
	return nil
}
