FROM golang:1.26.5@sha256:d52df9c279840adf958d017ebb275651ed8338b953d39817bc3633a2e6b1bbcc

ENV AUTH_CALLBACK_PATH="" REDIRECT_PORT="" PORT=""

# Expose OIDC server so we can access it in the tests
EXPOSE $PORT

WORKDIR /app

# Each instruction adds a few seconds to every image build, so the clone and
# build share one RUN.
RUN git clone --branch test https://github.com/openpubkey/oidc.git && \
    cd oidc && \
    go mod download && \
    go build -o /server -v ./example/server/dynamic

WORKDIR /app/oidc/

# Start example OIDC server on container startup
CMD ["sh", "-c", "AUTH_CALLBACK_PATH=${AUTH_CALLBACK_PATH} REDIRECT_PORT=${REDIRECT_PORT} PORT=${PORT} /server"]
