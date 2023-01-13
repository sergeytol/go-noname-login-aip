package users

import (
	"github.com/labstack/echo/v4"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/appdata"
	"gitlab.netprotect.com/nucleus/lab/go-login-api/internal/models"
	"net/http"
	"strings"
	"time"
)

func RetrieveUser(username string, appData *appdata.AppData) (models.UserModel, error) {
	var user models.UserModel
	row := appData.Db.QueryRow(`SELECT
                ci.UserName as username,
                ci.manPassword as password,
                ci.Email as email,
                cs.tier as tier, 
                cs.userStatus as userstatus,
                cs.nextCycle as nextcycle,
                cs.cuid as customer_id
            FROM customerInfo ci
            JOIN customerStatus cs on cs.cuid = ci.cid
            WHERE ci.UserName = ? or ci.UserName = ?`, username, strings.Replace(username, "@", "_", -1))
	if err := row.Scan(&user.Username, &user.Password, &user.Email, &user.Tier, &user.UserStatus, &user.NextCycle, &user.CustomerID); err != nil {
		return user, err
	}
	return user, nil
}

func MakeUserResponse(c echo.Context, user models.UserModel, oauthToken models.OAuthTokenModel) error {
	var accountType = 2
	var subEndEpoch = user.NextCycle
	if user.UserStatus > 5 {
		accountType = 3
		subEndEpoch = time.Now().Unix()
	}
	if user.Tier == 0 || user.Tier == 50 {
		accountType = 0
	}
	if user.Tier == 61 || user.Tier == 60 {
		accountType = 1
	}

	return c.JSON(http.StatusOK, &models.LoginResponse{
		Email:             user.Email,
		AccountType:       accountType,
		SubEndEpoch:       subEndEpoch,
		AccessToken:       oauthToken.AccessToken,
		RefreshToken:      oauthToken.RefreshToken,
		AccessExpireEpoch: oauthToken.AccessExpireEpoch,
	})
}
