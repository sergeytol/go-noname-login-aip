package models

type RequestBody struct {
	ApiKey       string `json:"api_key"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	RefreshToken string `json:"refresh_token"`
}

type PongResponse struct {
	Pong bool `json:"pong"`
}

type ErrorResponse struct {
	Code   int    `json:"code"`
	Reason string `json:"reason"`
}

type LoginResponse struct {
	Email             string `json:"email"`
	AccountType       int    `json:"account_type"`
	SubEndEpoch       int64  `json:"sub_end_epoch"`
	AccessToken       string `json:"access_token"`
	RefreshToken      string `json:"refresh_token"`
	AccessExpireEpoch int64  `json:"access_expire_epoch"`
}

type UserModel struct {
	Username   string
	Password   string
	Email      string
	Tier       int
	UserStatus int
	NextCycle  int64
	CustomerID int
}

type OAuthTokenJSON struct {
	Username     string `json:"username"`
	CreateTime   int64  `json:"create_time"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type OAuthTokenModel struct {
	Username          string
	CreateTime        int64
	AccessToken       string
	RefreshToken      string
	AccessExpireEpoch int64
}
