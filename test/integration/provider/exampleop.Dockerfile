FROM golang:1.26.1@sha256:595c7847cff97c9a9e76f015083c481d26078f961c9c8dca3923132f51fe12f1

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
