# Stage 1: Build the Go binary
FROM golang:1.25.1@sha256:76a94c4a37aaab9b1b35802af597376b8588dc54cd198f8249633b4e117d9fcc as builder

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
FROM opensuse/tumbleweed:latest@sha256:4739040b45d478fb41894f720ebfd2a6b564eb73ddc68ec2973f3387e7cc4928
# Install dependencies required for runtime (e.g., SSH server)
RUN zypper refresh && \
    zypper --non-interactive install sudo openssh-server openssh-clients telnet wget jq && \
    zypper clean --all && \
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
