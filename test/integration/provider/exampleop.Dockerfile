FROM golang:1.27.3@sha256:a386c44c1c90025ad5bc66feea3fef23052bef3bace3609f7e3e10e1f9314f45

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
