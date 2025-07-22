FROM golang:1.24.5@sha256:dd26b024adcdee20239479d884829d471fd821099b2f596f8f5d20b81bebca95

# Update/Upgrade
RUN apt-get update -y && apt-get upgrade -y

# Install dependencies, such as the SSH server
RUN apt-get install -y sudo openssh-server telnet jq

# Source:
# https://medium.com/@ratnesh4209211786/simplified-ssh-server-setup-within-a-docker-container-77eedd87a320
#
# Create an SSH user named "test". Make it a sudoer
RUN useradd -rm -d /home/test -s /bin/bash -g root -G sudo -u 1000 test
# Set password to "test"
RUN  echo "test:test" | chpasswd

# Make it so "test" user does not need to present password when using sudo
# Source: https://askubuntu.com/a/878705
RUN echo "test ALL=(ALL:ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/test

# Allow SSH access
RUN mkdir /var/run/sshd

# Expose SSH server so we can ssh in from the tests
EXPOSE 22

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy our repo
COPY . ./

# Build "opkssh" binary and write to the opk directory
RUN go build -v -o opksshbuild
RUN chmod +x ./scripts/install-linux.sh
RUN bash ./scripts/install-linux.sh --install-from=opksshbuild --no-sshd-restart

# Authorize GitHub provider for SSH logins
RUN echo "https://token.actions.githubusercontent.com github oidc" >> /etc/opk/providers

# Add integration test user as allowed email in policy (this directly tests
# policy "add" command)
ARG AUTHORIZED_REPOSITORY
ARG AUTHORIZED_REF
RUN opkssh add "test" "repo:${AUTHORIZED_REPOSITORY}:ref:${AUTHORIZED_REF}" "https://token.actions.githubusercontent.com"

# Start SSH server on container startup
CMD ["/usr/sbin/sshd", "-D"]
