FROM golang:1.25.0@sha256:9e56f0d0f043a68bb8c47c819e47dc29f6e8f5129b8885bed9d43f058f7f3ed6

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
