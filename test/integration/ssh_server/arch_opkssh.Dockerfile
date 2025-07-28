# Stage 1: Build the Go binary
FROM golang:1.24.5@sha256:ef5b4be1f94b36c90385abd9b6b4f201723ae28e71acacb76d00687333c17282 as builder

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

# Stage 2: Create a minimal ArchLinux-based image
FROM quay.io/archlinux/archlinux:latest@sha256:3fb843af2bfadb4b81c624c56a1199f9b012db45994a0e89a18a99fe795c449e
# Install dependencies required for runtime (e.g., SSH server)
RUN pacman -Syu --noconfirm && \
    pacman -Sy openssh inetutils wget jq sudo --noconfirm && \
    pacman -Scc --noconfirm


# Source:
# https://medium.com/@ratnesh4209211786/simplified-ssh-server-setup-within-a-docker-container-77eedd87a320
#
# Create an SSH user named "test". Make it a sudoer

# Create the sudoers.d directory if it doesn't exist
RUN mkdir -p /etc/sudoers.d

# Create an SSH user named "test" and make it a sudoer
RUN useradd -m -d /home/test -s /bin/bash -g root -G wheel -u 1000 test

# Set password for "test" user to "test"
RUN echo "test:test" | chpasswd

# Make it so "test" user does not need to present password when using sudo
RUN echo "test ALL=(ALL:ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/test

# Create unprivileged user named "test2"
RUN useradd -rm -d /home/test2 -s /bin/bash -u 1001 test2
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
