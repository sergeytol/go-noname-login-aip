# go-noname-login-api

Experiment - Noname login service ported from PHP to Go

It requires [dev-core](https://gitlab.*********.com/noname/dev-core) to work

## Setup

```shell script
cp .env.dist .env
docker-compose build
```

## Run
```shell script
docker-compose up -d
```

The service will be available on 1323 port in 10-20 sec

## Examples

```shell script
curl --location --request POST '0.0.0.0:1323/login' \
--header 'X-PRETTY-PLEASE: dont_ban' \
--header 'Content-Type: application/json' \
--header 'Cookie: PHPSESSID=6788d541c01a5bfbbc87c64848492528' \
--data-raw '{
    "api_key": "1e3c1bd01094cb59b77526a77ba25d03",
    "username": "226_support@example.com",
    "password": "qwerty123"
}'
```

Result:
```json
{
    "email": "226_support@example.com",
    "account_type": 2,
    "sub_end_epoch": 1664290534,
    "access_token": "0e6c9069bbccb7765736047e2b337d60360374f2",
    "refresh_token": "ed9916c6bc591dca14b1928ef8ecc8da74851040",
    "access_expire_epoch": 1635352686
}
```