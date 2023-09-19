package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var (
	DB               *gorm.DB
	secretKey        = []byte("your-secret-key")
	refreshSecretKey = []byte("your-refresh-secret-key")
)

func main() {
	ConnectDatabase()

	e := echo.New()
	//e.GET("", func(c echo.Context) error {
	// 	return c.String(200, "ok")
	// })
	e.POST("/sign", SignHandler)
	e.POST("/login", LoginHandler)
	e.POST("/refresh", refreshTokenHandler)
	e.GET("/user", userHandler, authMiddleware("USER"))
	e.GET("/admin", adminHandler, authMiddleware("ADMIN"))

	e.Start("0.0.0.0:" + "8080")

}
func refreshTokenHandler(echo echo.Context) error {
	refreshToken := echo.Request().PostFormValue("refresh_token")
	if refreshToken == "" {
		return echo.JSON(http.StatusBadRequest, "refresh token undetected")
	}
	token, err := jwt.Parse(refreshToken, func(t *jwt.Token) (interface{}, error) {
		return refreshSecretKey, nil
	})
	if err != nil || !token.Valid {
		echo.JSON(400, errors.New("invalid token"))
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		echo.JSON(500, errors.New(" invalid refresh token"))
	}
	user := Users{
		ID:       int(claims["id"].(float64)),
		Username: claims["username"].(string),
		Role:     claims["role"].(string),
	}
	newTokens, err := createTokens(user)
	if err != nil {
		return echo.JSON(500, err)
	}
	return echo.JSON(201, newTokens)

}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Users struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Password string `json:"password"`
}

func SignHandler(e echo.Context) error {
	var signData *Users
	err := e.Bind(&signData)
	if err != nil || signData == nil {
		return e.String(http.StatusBadRequest, "invalid sign")
	}
	if signData.Password == "" || signData.Username == "" || signData.Role == "" {
		return e.String(http.StatusBadRequest, "field request uncomplite")
	}
	if isUserExist(signData.Username) {
		return e.JSON(400, errors.New("username hasbeen used"))
	}
	newPassword, err := hashingPassword(signData.Password)
	if err != nil {
		return e.JSON(500, err.Error())
	}
	signData.Password = newPassword
	result := DB.Create(&signData)
	if result.Error != nil {
		return e.JSON(400, err.Error())
	}
	return e.JSON(201, signData)
}
func isUserExist(username string) bool {
	var data Users
	result := DB.Where("username=?", username).Find(&data)
	if result.Error != nil || data.Username == "" {
		return false
	}
	return true
}
func hashingPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}
func comparePassword(hashPassword string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashPassword), []byte(password))
}

func LoginHandler(e echo.Context) error {

	var loginData *Users
	err := e.Bind(&loginData)
	if err != nil {
		return e.String(http.StatusBadRequest, "invalid login")
	}
	if loginData.Password == "" || loginData.Username == "" {
		return e.String(http.StatusBadRequest, "field request uncomplite")
	}
	var userData Users
	result := DB.Where("username=? ", loginData.Username).Find(&userData)
	if result.Error != nil {
		return e.JSON(400, result.Error)
	}
	if userData.ID == 0 {
		return e.JSON(400, ("user not found"))
	}
	err = comparePassword(userData.Password, loginData.Password)
	if err != nil {
		return e.JSON(400, "wrong password")
	}

	//generate token
	token, err := createTokens(userData)
	if err != nil {
		return e.JSON(500, err.Error())
	}
	return e.JSON(200, token)
}
func generateToken(user Users, key []byte, expiration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = user.ID
	claims["username"] = user.Username
	claims["role"] = user.Role
	claims["exp"] = expiration

	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func createTokens(user Users) (Tokens, error) {
	accessToken, err := generateToken(user, secretKey, time.Hour*24)
	if err != nil {
		return Tokens{}, err
	}
	refreshToken, err := generateToken(user, refreshSecretKey, time.Hour*24*30)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func authMiddleware(role string) echo.MiddlewareFunc {
	return func(Next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tokenString := c.Request().Header.Get("Authorization")
			if tokenString == "" {
				return c.JSON(http.StatusUnauthorized, error.Error(errors.New("unauthorize")))
			}

			token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
				return secretKey, nil
			})
			if err != nil || !token.Valid {
				return c.JSON(http.StatusForbidden, errors.New("unauthorize"))
			}
			claims, ok := token.Claims.(jwt.MapClaims)
			if ok || claims["role"] == role {
				return Next(c)
			}
			return c.JSON(http.StatusForbidden, errors.New("unauthorize"))

		}
	}

}

func userHandler(c echo.Context) error {

	return c.JSON(200, "user")
}
func adminHandler(c echo.Context) error {

	return c.JSON(200, "admin")
}

func ConnectDatabase() {
	dsn := "host=localhost user=postgres password=007944 dbname=bank port=5432 sslmode=disable TimeZone=Asia/Shanghai"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{NamingStrategy: schema.NamingStrategy{
		SingularTable: true,
	}})

	if err != nil {
		fmt.Printf("Error")
		return
	}
	DB = db
}
