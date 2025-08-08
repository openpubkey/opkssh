FROM golang:1.24.6@sha256:2c89c41fb9efc3807029b59af69645867cfe978d2b877d475be0d72f6c6ce6f6

ENV AUTH_CALLBACK_PATH ""
ENV REDIRECT_PORT ""
ENV PORT ""

# Expose OIDC server so we can access it in the tests
EXPOSE $PORT

WORKDIR /app

RUN git clone --branch test https://github.com/openpubkey/oidc.git

WORKDIR /app/oidc/

RUN go mod download

RUN go build -o /server -v ./example/server/dynamic

# Start example OIDC server on container startup
CMD ["sh", "-c", "AUTH_CALLBACK_PATH=${AUTH_CALLBACK_PATH} REDIRECT_PORT=${REDIRECT_PORT} PORT=${PORT} /server"]
