package ip_banning

import (
	"github.com/gomodule/redigo/redis"
	"github.com/labstack/echo/v4"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/appdata"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/models"
	"net/http"
)

func IsIPBanned(ip string, appData *appdata.AppData) (bool, error) {
	for _, item := range appData.WhitelistedIPs {
		if item == ip {
			return false, nil
		}
	}

	/*
		Because REDIS cannot decrement all keys, we will increment IP addresses and verify that they have not
		exceeded 9 bannable requests within a _rolling_ 300 second period. After 300 seconds they are unbanned
		and can then do another 10 bannable requests.
	*/
	redisClient := appData.RedisPool.Get()
	defer redisClient.Close()

	count, err := redisClient.Do("GET", appData.RedisIPScorePrefix+ip)

	if count == nil {
		return false, err
	}
	countInt, err := redis.Int(count, nil)
	if count == nil {
		return false, err
	}

	return countInt > 9, nil
}

func IncrementIPScore(ip string, appData *appdata.AppData) error {
	redisClient := appData.RedisPool.Get()
	defer redisClient.Close()

	_, err := redisClient.Do("INCR", appData.RedisIPScorePrefix+ip)
	if err != nil {
		return err
	}

	_, err = redisClient.Do("EXPIRE", appData.RedisIPScorePrefix+ip, 300)
	if err != nil {
		return err
	}

	return nil
}

func IPBanningMiddleware(next echo.HandlerFunc, appData *appdata.AppData) echo.HandlerFunc {
	return func(c echo.Context) error {
		xPrettyPlease := c.Request().Header.Get("X-PRETTY-PLEASE")
		if xPrettyPlease == "dont_ban" {
			if err := next(c); err != nil {
				c.Error(err)
			}
			return nil
		}
		banned, err := IsIPBanned(c.RealIP(), appData)
		if err != nil {
			c.Error(err)
			return err
		}
		if banned == true {
			return c.JSON(http.StatusForbidden, &models.ErrorResponse{
				Code:   1099,
				Reason: "Too many failed attempts",
			})
		}

		if err := next(c); err != nil {
			c.Error(err)
			return err
		}
		if c.Response().Status == http.StatusBadRequest || c.Response().Status == http.StatusUnauthorized {
			err = IncrementIPScore(c.RealIP(), appData)
			if err != nil {
				c.Logger().Fatal(err)
				return err
			}
		}
		return nil
	}
}
