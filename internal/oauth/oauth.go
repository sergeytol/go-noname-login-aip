package oauth

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/djimenez/iconv-go"
	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/appdata"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/models"
	"golang.org/x/crypto/md4"
	"strings"
	"time"
)

func GetAuthToken(c echo.Context) (string, error) {
	val := c.Request().Header.Get("Authorization")
	if val == "" {
		return "", errors.New("no access token")
	}
	return strings.Fields(val)[1], nil
}

func IsAuthTokenSet(c echo.Context) bool {
	val := c.Request().Header.Get("Authorization")
	if val == "" || val == "Bearer null" {
		return false
	}
	return true
}

func VerifyAccessToken(token string, appData *appdata.AppData) (models.OAuthTokenModel, error) {
	var oauthTokenJSON models.OAuthTokenJSON
	var oauthToken models.OAuthTokenModel

	redisClient := appData.RedisPool.Get()
	defer redisClient.Close()

	oauthTokenJSONString, err := redis.String(redisClient.Do("GET", appData.RedisOauthPrefix+token))
	if err != nil {
		return oauthToken, err
	}

	err = json.Unmarshal([]byte(fmt.Sprint(oauthTokenJSONString)), &oauthTokenJSON)
	if err != nil {
		return oauthToken, err
	}

	return models.OAuthTokenModel{
		Username:          oauthTokenJSON.Username,
		CreateTime:        oauthTokenJSON.CreateTime,
		AccessToken:       oauthTokenJSON.AccessToken,
		RefreshToken:      oauthTokenJSON.RefreshToken,
		AccessExpireEpoch: oauthTokenJSON.CreateTime + appData.AccessTokenTTLSec,
	}, nil
}

func IsRefreshTokenExpired(oauthToken models.OAuthTokenModel, appData *appdata.AppData) bool {
	return time.Now().Unix() > oauthToken.CreateTime+appData.RefreshTokenTTLSec
}

func IsAccessTokenExpired(oauthToken models.OAuthTokenModel, appData *appdata.AppData) bool {
	return time.Now().Unix() > oauthToken.CreateTime+appData.AccessTokenTTLSec
}

func RefreshAccessToken(oauthToken models.OAuthTokenModel, appData *appdata.AppData) (models.OAuthTokenModel, error) {
	newOauthToken, err := ProvisionOAuth(oauthToken.Username, appData)
	if err != nil {
		return newOauthToken, err
	}

	err = DeleteAccessToken(oauthToken.AccessToken, appData)
	if err != nil {
		return newOauthToken, err
	}

	return newOauthToken, nil
}

func DeleteAccessToken(accessToken string, appData *appdata.AppData) error {
	redisClient := appData.RedisPool.Get()
	defer redisClient.Close()

	_, err := redisClient.Do("DEL", appData.RedisOauthPrefix+accessToken)
	if err != nil {
		return err
	}
	return nil
}

func VerifyAPIKey(apiKey string, appData *appdata.AppData) string {
	for key, value := range appData.ApiKeysMap {
		if apiKey == value {
			return key
		}
	}
	return ""
}

func NtlmHash(str string) string {
	input, _ := iconv.ConvertString(str, "utf-8", "utf-16le")
	hasher := md4.New()
	hasher.Write([]byte(input))
	hashed := hex.EncodeToString(hasher.Sum(nil))
	return strings.ToUpper(hashed)
}

func VerifyPassword(password string, hashedPassword string) bool {
	return NtlmHash(password) == hashedPassword
}

func ProvisionOAuth(username string, appData *appdata.AppData) (models.OAuthTokenModel, error) {

	var oauthToken models.OAuthTokenModel

	s := username + "access" + uuid.New().String()
	h := sha1.New()
	h.Write([]byte(s))
	accessToken := hex.EncodeToString(h.Sum(nil))
	s = username + "refresh" + uuid.New().String()
	h = sha1.New()
	h.Write([]byte(s))
	refreshToken := hex.EncodeToString(h.Sum(nil))

	createTime := time.Now().Unix()

	oauthInsertJSON, err := json.Marshal(&models.OAuthTokenJSON{
		Username:     username,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		CreateTime:   createTime,
	})
	if err != nil {
		return oauthToken, err
	}

	redisClient := appData.RedisPool.Get()
	defer redisClient.Close()

	_, err = redisClient.Do("SETEX", appData.RedisOauthPrefix+accessToken, appData.RefreshTokenTTLSec, oauthInsertJSON)
	if err != nil {
		return oauthToken, err
	}

	oauthToken = models.OAuthTokenModel{
		Username:          username,
		CreateTime:        createTime,
		AccessToken:       accessToken,
		RefreshToken:      refreshToken,
		AccessExpireEpoch: createTime + appData.AccessTokenTTLSec,
	}
	return oauthToken, nil
}
