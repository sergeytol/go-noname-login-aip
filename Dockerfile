FROM golang:1.17 as base
FROM base as dev
RUN curl -sSfL https://raw.githubusercontent.com/cosmtrek/air/master/install.sh | sh -s -- -b $(go env GOPATH)/bin
WORKDIR /app
RUN mkdir -p /app/logs
CMD ["air"]
