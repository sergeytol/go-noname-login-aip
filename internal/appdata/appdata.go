package appdata

import (
	"database/sql"
	"github.com/gomodule/redigo/redis"
	"github.com/labstack/gommon/log"
)

type AppData struct {
	ApiKeysMap         map[string]string
	ApiKeyClient       string
	Db                 *sql.DB
	RedisPool          *redis.Pool
	RedisClient        redis.Conn
	ElkLogger		   *log.Logger
	AccessTokenTTLSec  int64
	RefreshTokenTTLSec int64
	RedisOauthPrefix   string
	RedisIPScorePrefix string
	WhitelistedIPs     []string
}
