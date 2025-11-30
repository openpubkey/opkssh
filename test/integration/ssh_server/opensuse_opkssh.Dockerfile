# Stage 1: Build the Go binary
FROM golang:1.25.4@sha256:698183780de28062f4ef46f82a79ec0ae69d2d22f7b160cf69f71ea8d98bf25d as builder

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy our repo
COPY . ./

# Copy the source code and build the binary
ARG ISSUER_PORT="9998"
RUN go build -v -o opksshbuild

# Stage 2: Create a minimal openSUSE-Tumbleweed-based image
FROM opensuse/tumbleweed:latest@sha256:4d70524d29e946886e561b2bce5f70b6c7d3a8d5707eea738050bb33f32bbfb4

# Install dependencies required for runtime (e.g., SSH server)
RUN zypper refresh && \
    zypper -n ref && \
    zypper -n dup --allow-vendor-change && \
    zypper -n in --no-recommends \
        sudo openssh-server openssh-clients openssl ca-certificates telnet wget jq && \
    zypper -n clean --all && \
    rm /var/log/zypp/history && \
    rm /var/log/zypper.log

# Source:
# https://medium.com/@ratnesh4209211786/simplified-ssh-server-setup-within-a-docker-container-77eedd87a320
#
# Create an SSH user named "test". Make it a sudoer
RUN useradd -rm -d /home/test -s /bin/bash -g root -u 480 test
# Set password to "test"
RUN  echo "test:test" | chpasswd

# Make it so "test" user does not need to present password when using sudo
# Source: https://askubuntu.com/a/878705
RUN echo "test ALL=(ALL:ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/test

# Create unprivileged user named "test2"
RUN useradd -rm -d /home/test2 -s /bin/bash -u 481 test2
# Set password to "test"
RUN  echo "test2:test" | chpasswd

# Allow SSH access
RUN mkdir /var/run/sshd

# Expose SSH server so we can ssh in from the tests
EXPOSE 22

WORKDIR /app

# Copy binary and install script from builder
COPY --from=builder /app/opksshbuild ./opksshbuild
COPY --from=builder /app/scripts/install-linux.sh install-linux.sh

# Run install script to install/configure opkssh
RUN chmod +x install-linux.sh
RUN bash ./install-linux.sh --install-from=opksshbuild --no-sshd-restart

RUN opkssh --version
RUN ls -l /usr/local/bin
RUN printenv PATH

ARG ISSUER_PORT="9998"
RUN echo "http://oidc.local:${ISSUER_PORT}/ web oidc_refreshed" >> /etc/opk/providers

# Add integration test user as allowed email in policy (this directly tests
# policy "add" command)
ARG BOOTSTRAP_POLICY
RUN if [ -n "$BOOTSTRAP_POLICY" ] ; then opkssh add "test" "test-user@zitadel.ch" "http://oidc.local:${ISSUER_PORT}/"; else echo "Will not init policy" ; fi

# Generate SSH host keys
RUN ssh-keygen -A

# Start the SSH server on container startup
CMD ["/usr/sbin/sshd", "-D"]
