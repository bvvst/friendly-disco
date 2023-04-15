package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

type Message struct {
	Content string `json:"content"`
}

type DBMessage struct {
	Content  string `json:"content"`
	UserAddr string `json:"user_addr"`
}

var jwtSecret string
var serviceKey string

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	serviceKey = os.Getenv("SERVICE_KEY")
	jwtSecret = os.Getenv("JWT_SECRET")
}

func main() {

	fmt.Println(serviceKey)
	fmt.Println(jwtSecret)
	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		c.Response().Header.Set("Access-Control-Allow-Origin", "*")
		c.Response().Header.Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
		c.Response().Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		if c.Method() == "OPTIONS" {
			return c.SendStatus(200)
		}
		return c.Next()
	})

	app.Post("/message", func(c *fiber.Ctx) error {
		m := new(Message)
		if err := c.BodyParser(m); err != nil {
			fmt.Println(err)
			return c.SendString("Error Parsing")
		}

		token := c.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")

		decodedToken, err := decodeJWT(token, jwtSecret)
		if err != nil {
			fmt.Println(err)
			return c.SendString("Error Decoding")

		}

		claims, ok := decodedToken.Claims.(jwt.MapClaims)
		if !ok {
			fmt.Println("Error extracting claims from token")
			return c.SendString("Error Extracting Claims")
		}

		userAddr, ok := claims["addr"].(string)
		if !ok {
			fmt.Println("Addr isn't in claims")
			return c.SendString("Error Extracting Claims")
		}

		_, err = sendMessage(DBMessage{Content: m.Content, UserAddr: userAddr})
		if err != nil {
			fmt.Println("Error saving message")
			return c.SendString("Error saving message")
		}

		return c.SendString("Hello, World!")
	})

	app.Listen(":3000")
}

func sendMessage(m DBMessage) (*http.Response, error) {
	// Marshal the struct to JSON
	jsonData, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	// Create a new HTTP request
	req, err := http.NewRequest("POST", "https://lignorhoomxeyhyetgdf.supabase.co/rest/v1/messages", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	// Set the Content-Type header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", serviceKey)
	req.Header.Set("Authorization", "Bearer "+serviceKey)

	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func decodeJWT(tokenString string, secretKey string) (*jwt.Token, error) {
	// Define a function that returns the secret key for validation
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	}

	// Parse the token using the key function
	token, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		return nil, err
	}

	// Check if the token is valid
	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return token, nil
	} else {
		return nil, fmt.Errorf("invalid token")
	}
}
