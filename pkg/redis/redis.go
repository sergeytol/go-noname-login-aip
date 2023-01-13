package redis

import "github.com/gomodule/redigo/redis"

func NewRedisPool(network string, address string) *redis.Pool {
	return &redis.Pool{
		MaxIdle:   80,
		MaxActive: 12000,
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial(network, address)
			if err != nil {
				panic(err.Error())
			}
			return c, err
		},
	}
}
