package main

import (
	"context"
	"database/sql"
	"github.com/joho/godotenv"
	"github.com/labstack/gommon/log"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/appdata"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/handlers"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/middleware/ip_banning"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/models"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/oauth"
	envtools "gitlab.netprotect.com/nucleus/lab/go-login-api/pkg/env"
	redistools "gitlab.netprotect.com/nucleus/lab/go-login-api/pkg/redis"
	"net/http"
	"os"
	"os/signal"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var appData *appdata.AppData

func PingEndpoint(c echo.Context) error {
	resp := &models.PongResponse{
		Pong: true,
	}
	return c.JSON(http.StatusOK, resp)
}

func LoginEndpoint(c echo.Context) error {

	body := new(models.RequestBody)
	if err := c.Bind(body); err != nil {
		return c.JSON(http.StatusBadRequest, &models.ErrorResponse{
			Code:   1001,
			Reason: "API Key Invalid",
		})
	}

	if oauth.IsAuthTokenSet(c) == true {
		return handlers.HandleOAuthRequest(c, body, appData)
	}

	apiKey := body.ApiKey
	if apiKey == "" {
		return c.JSON(http.StatusBadRequest, &models.ErrorResponse{
			Code:   1001,
			Reason: "API Key Invalid",
		})
	}

	apiKeyClient := oauth.VerifyAPIKey(apiKey, appData)
	if apiKeyClient == "" {
		return c.JSON(http.StatusBadRequest, &models.ErrorResponse{
			Code:   1001,
			Reason: "API Key Invalid",
		})
	}

	if body.Username == "" || body.Password == "" {
		return c.JSON(http.StatusBadRequest, &models.ErrorResponse{
			Code:   1000,
			Reason: "Password is a required field",
		})
	}

	return handlers.HandleCredentialRequest(c, body, appData)
}

func IPBanningMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return ip_banning.IPBanningMiddleware(next, appData)
}

func main() {

	var err error

	appData = &appdata.AppData{
		RedisOauthPrefix:   "NONAME:OAUTH:",
		RedisIPScorePrefix: "NONAME:IPSCORE:",
		WhitelistedIPs: []string{
			"127.0.0.1",
			"localhost",
			// these 3 IP's are the outbounds for WP office which NAT's as 1 conglomerate
			"205.185.202.20",
			"205.185.202.10",
			"205.185.201.10",
			// temp hacks to allow proxy domains due to invalid IP address handling
			"52.15.206.57",
			"52.53.189.192",
			"52.47.207.84",
			"34.221.106.117",
			"52.53.200.133",
			"54.190.138.176",
			"3.14.85.186",
		},
	}

	// API keys

	appData.ApiKeysMap = make(map[string]string)
	appData.ApiKeysMap["macos"] = "f7bf6a56965f4fdd8eb10142defbbdf4"
	appData.ApiKeysMap["ios"] = "185f600f32cee535b0bef41ad77c1acd"
	appData.ApiKeysMap["ios_old"] = "3d5fb9fe893a3f4298f51241544e1d01"
	appData.ApiKeysMap["windows"] = "619a91cf2e398a46dcc97bb961f3a23b"
	appData.ApiKeysMap["android"] = "15cb936e6d19cd7db1d6f94b96017541"
	appData.ApiKeysMap["other"] = "1e3c1bd01094cb59b77526a77ba25d03"

	// Create Echo app

	e := echo.New()
	e.Logger.SetLevel(log.INFO)

	// env vars
	err = godotenv.Load(".env")
	if err != nil {
		e.Logger.Fatal("Error loading .env file")
		panic(err)
	}

	appData.AccessTokenTTLSec = int64(envtools.GetEnvAsInt("ACCESS_TTL", 252000))
	appData.RefreshTokenTTLSec = int64(envtools.GetEnvAsInt("REFRESH_TTL", 108000))

	// DB connection

	appData.Db, err = sql.Open("mysql", envtools.GetEnv("DB_DSN", ""))
	if err != nil {
		e.Logger.Fatal(err)
		panic(err)
	}
	defer appData.Db.Close()

	pingErr := appData.Db.Ping()
	if pingErr != nil {
		e.Logger.Fatal(pingErr)
		panic(err)
	}

	// Redis

	appData.RedisPool = redistools.NewRedisPool(os.Getenv("REDIS_NETWORK"), os.Getenv("REDIS_ADDRESS"))

	// ELK logger

	appData.ElkLogger = log.New("ELK")
	file, err := os.OpenFile(os.Getenv("PATH_TO_ELK_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY,  0666)
	if err != nil {
		e.Logger.Fatal(err)
		panic(err)
	}
	appData.ElkLogger.SetOutput(file)

	// Routing

	e.Use(middleware.Logger())
	e.Use(middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
		handlers.ElkLoggerHandler(c, reqBody, resBody, appData)
	}))
	e.GET("/ping", PingEndpoint)
	e.POST("/login", LoginEndpoint, IPBanningMiddleware)

	// Start server

	go func() {
		if err := e.Start(os.Getenv("API_SERVER_ADDR")); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal("shutting down the server")
		}
	}()

	// Graceful shutdown

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
}
