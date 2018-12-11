package main

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
)

const (
	SecretKey = "test jwt"
)

type UserCredentials struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Data string `json:"data"`
}

type Token struct {
	Token string `json:"token"`
}

func main() {
	router := gin.Default()

	router.POST("/login", LoginHandler)

	router.GET("/resource", ValidateTokenMiddleware(), ProtectedHandler)

	log.Println("Now listening...")

	err := router.Run(":8080")
	if err != nil {
		log.Println("Server Run error", err)
	}
}

func ProtectedHandler(c *gin.Context) {
	response := Response{"访问成功"}
	c.JSON(http.StatusOK, response)
}

func LoginHandler(c *gin.Context) {
	var user UserCredentials
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusUnauthorized, Response{"数据格式错误"})
		return
	}

	if strings.ToLower(user.Username) != "someone" {
		if user.Password != "p@ssword" {
			c.JSON(http.StatusUnauthorized, Response{"用户名或密码错误"})
			return
		}
	}

	token := jwt.New(jwt.SigningMethodHS256)
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * time.Duration(1)).Unix()
	claims["iat"] = time.Now().Unix()
	token.Claims = claims

	tokenString, err := token.SignedString([]byte(SecretKey))
	if err != nil {
		c.JSON(http.StatusUnauthorized, Response{"生成token出错"})
		return
	}

	response := Token{tokenString}
	c.JSON(http.StatusOK, response)
}

func ValidateTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := request.ParseFromRequest(c.Request, request.AuthorizationHeaderExtractor,
			func(token *jwt.Token) (interface{}, error) {
				return []byte(SecretKey), nil
			})
		if err == nil {
			if token.Valid {
				c.Next()
			} else {
				c.JSON(http.StatusUnauthorized, Response{"无效的token"})
				c.Abort()
			}
		} else {
			c.JSON(http.StatusUnauthorized, Response{err.Error()})
			c.Abort()
		}
	}
}
