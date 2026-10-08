# Stage 1: Build the Go binary
FROM golang:1.26.5@sha256:d52df9c279840adf958d017ebb275651ed8338b953d39817bc3633a2e6b1bbcc as builder

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy our repo
COPY . ./

# Build the binary
RUN go build -v -o opksshbuild

# Stage 2: Create a minimal ArchLinux-based image
FROM quay.io/archlinux/archlinux:latest

# Install dependencies required for runtime (e.g., SSH server)
RUN pacman -Syu --noconfirm && \
    pacman -Sy openssh inetutils wget jq sudo --noconfirm && \
    pacman -Scc --noconfirm

# Each instruction adds a few seconds to every image build, so related steps
# share one RUN.
#
# Create an SSH user named "test" and make it a sudoer that does not need to
# present a password, create an unprivileged user named "test2" (both with
# password "test"), and allow SSH access.
#
# Source:
# https://medium.com/@ratnesh4209211786/simplified-ssh-server-setup-within-a-docker-container-77eedd87a320
RUN mkdir -p /etc/sudoers.d && \
    useradd -m -d /home/test -s /bin/bash -g root -G wheel -u 1000 test && \
    echo "test:test" | chpasswd && \
    echo "test ALL=(ALL:ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/test && \
    useradd -rm -d /home/test2 -s /bin/bash -u 1001 test2 && \
    echo "test2:test" | chpasswd && \
    mkdir /var/run/sshd

# Expose SSH server so we can ssh in from the tests
EXPOSE 22

WORKDIR /app

# Copy binary and install script from builder
COPY --from=builder /app/opksshbuild /app/scripts/install-linux.sh ./

# Run install script to install/configure opkssh, and generate SSH host keys
RUN bash ./install-linux.sh --install-from=opksshbuild --no-sshd-restart && \
    opkssh --version && \
    ls -l /usr/local/bin && \
    printenv PATH && \
    ssh-keygen -A

# Trust the test OIDC issuer and, if BOOTSTRAP_POLICY is set, add the
# integration test user as allowed email in policy (this directly tests policy
# "add" command)
ARG ISSUER_PORT="9998"
ARG BOOTSTRAP_POLICY
RUN echo "http://oidc.local:${ISSUER_PORT}/ web oidc_refreshed" >> /etc/opk/providers && \
    if [ -n "$BOOTSTRAP_POLICY" ] ; then opkssh add "test" "test-user@zitadel.ch" "http://oidc.local:${ISSUER_PORT}/"; else echo "Will not init policy" ; fi

# Start the SSH server on container startup
CMD ["/usr/sbin/sshd", "-D"]
