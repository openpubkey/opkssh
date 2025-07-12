FROM ubuntu:noble@sha256:440dcf6a5640b2ae5c77724e68787a906afb8ddee98bf86db94eea8528c2c076

# Update/Upgrade
RUN apt-get update -y && apt-get upgrade -y

# Install dependencies, such as the SSH server
RUN apt-get install -y sudo openssh-server

# Source:
# https://medium.com/@ratnesh4209211786/simplified-ssh-server-setup-within-a-docker-container-77eedd87a320
#
# Create an SSH user named "test". Make it a sudoer
RUN useradd -rm -d /home/test -s /bin/bash -g root -G sudo -u 1000 test
# Set password to "test"
RUN echo 'test:test' | chpasswd

# Allow SSH access
RUN mkdir /var/run/sshd

# Expose SSH server so we can ssh in from the tests
EXPOSE 22

# Start SSH server on container startup
CMD ["/usr/sbin/sshd", "-D"]
