package handlers

import (
	"database/sql"
	"encoding/json"
	"github.com/gomodule/redigo/redis"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/appdata"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/models"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/oauth"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/users"
	string_helpers "gitlab.netprotect.com/nucleus/lab/go-login-api/pkg"
	"net/http"
)

func HandleOAuthRequest(c echo.Context, body *models.RequestBody, appData *appdata.AppData) error {
	accessToken, err := oauth.GetAuthToken(c)
	if err != nil {
		c.Logger().Error(err)
		return err
	}

	oauthToken, err := oauth.VerifyAccessToken(accessToken, appData)
	if err == redis.ErrNil {
		return c.JSON(http.StatusUnauthorized, &models.ErrorResponse{
			Code:   1001,
			Reason: "Bearer Token Invalid",
		})
	} else if err != nil {
		c.Logger().Error(err)
		return err
	}

	if body.RefreshToken == "" || body.RefreshToken != oauthToken.RefreshToken {
		return c.JSON(http.StatusForbidden, &models.ErrorResponse{
			Code:   1101,
			Reason: "Refresh token invalid",
		})
	}

	if oauth.IsRefreshTokenExpired(oauthToken, appData) {
		return c.JSON(http.StatusForbidden, &models.ErrorResponse{
			Code:   1102,
			Reason: "Refresh token expired",
		})
	}

	newOauthToken, err := oauth.RefreshAccessToken(oauthToken, appData)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, &models.ErrorResponse{
			Code:   1009,
			Reason: "Could not provision OAuth",
		})
	}

	if oauth.IsAccessTokenExpired(oauthToken, appData) {
		return c.JSON(http.StatusForbidden, &models.ErrorResponse{
			Code:   1105,
			Reason: "Bearer token expired",
		})
	}

	user, err := users.RetrieveUser(newOauthToken.Username, appData)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusUnauthorized, &models.ErrorResponse{
				Code:   1100,
				Reason: "The username associated with this token could not be found",
			})
		}
		return err
	}

	return users.MakeUserResponse(c, user, newOauthToken)
}

func HandleCredentialRequest(c echo.Context, body *models.RequestBody, appData *appdata.AppData) error {
	user, err := users.RetrieveUser(body.Username, appData)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusUnauthorized, &models.ErrorResponse{
				Code:   1100,
				Reason: "The username or password provided is incorrect",
			})
		}
		return err
	}

	if oauth.VerifyPassword(body.Password, user.Password) == false {
		return c.JSON(http.StatusUnauthorized, &models.ErrorResponse{
			Code:   1100,
			Reason: "The username or password provided is incorrect",
		})
	}

	oauthToken, err := oauth.ProvisionOAuth(body.Username, appData)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, &models.ErrorResponse{
			Code:   1009,
			Reason: "Could not provision OAuth",
		})
	}

	return users.MakeUserResponse(c, user, oauthToken)
}

func ElkLoggerHandler(c echo.Context, reqBody, resBody []byte, appData *appdata.AppData) error {

	logJSON := log.JSON{
		"ip_address": c.RealIP(),
		"content_type": c.Request().Header.Get("Content-Type"),
		"endpoint": c.Request().RequestURI,
		"method": c.Request().Method,
		"query_params": c.QueryParams().Encode(),
		"authorization_header": c.Request().Header.Get("Authorization"),
		"meta_data": make([]string, 0),
	}
	defer appData.ElkLogger.Infoj(logJSON)

	// Log request data

	if !string_helpers.IsJSON(string(reqBody)) {
		logJSON["body"] = "Invalid JSON"
	} else {
		var bodyMap map[string]interface{}
		err := json.Unmarshal(reqBody, &bodyMap)
		if err != nil {
			c.Error(err)
			return err
		}
		_, ok := bodyMap["password"]
		if ok {
			bodyMap["password"] = true
		}
		logJSON["body"] = bodyMap
	}

	// Log response data

	var bodyMap map[string]interface{}
	err := json.Unmarshal(resBody, &bodyMap)
	if err != nil {
		c.Error(err)
		return err
	}
	logJSON["response_body"] = bodyMap
	logJSON["response_code"] = c.Response().Status

	return nil
}