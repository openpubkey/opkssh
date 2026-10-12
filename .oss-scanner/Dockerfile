# Build environment for Anthropic's OSS Scanner (https://red.anthropic.com/oss-scanner/).
# The scanner builds this with the repository root as the build context. Network access is
# available only while this image builds; everything the scanning agent needs must be fetched here.
FROM golang:1.26-trixie

ENV DEBIAN_FRONTEND=noninteractive \
    CGO_ENABLED=1 \
    GOTOOLCHAIN=local

# openssh-server lets the agent wire `opkssh verify` into a real sshd as AuthorizedKeysCommand.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git jq openssh-client openssh-server procps sudo \
    && rm -rf /var/lib/apt/lists/*

# Scanner contract: the checkout lives inside the image at /src.
COPY . /src
WORKDIR /src

# Fetch every module, including those only used by the integration tests.
RUN go mod download \
    && go test -tags=integration -count=1 -run '^$' ./... >/dev/null

# Build opkssh and install it the way an admin would, so /etc/opk, the opksshuser account,
# the sudoers rule and the sshd_config AuthorizedKeysCommand lines all exist in the image.
RUN go build -o /usr/local/bin/opkssh-build . \
    && bash ./scripts/install-linux.sh --install-from=/usr/local/bin/opkssh-build --no-sshd-restart

# Baseline unit tests. A failure is reported but does not fail the build.
# (test/integration needs Docker and live containers, so it is compiled above but not run.)
RUN go test -count=1 ./... || echo "WARNING: opkssh unit tests reported failures"

# Reproducers and patches must build with the network disabled.
ENV GOPROXY=off \
    GOSUMDB=off

CMD ["bash"]
