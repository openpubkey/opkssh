FROM golang:1.26.0@sha256:c83e68f3ebb6943a2904fa66348867d108119890a2c6a2e6f07b38d0eb6c25c5

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
