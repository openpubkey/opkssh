FROM ubuntu:noble@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

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
# This directory is automatically created on the latest docker image
# RUN mkdir /var/run/sshd

# Expose SSH server so we can ssh in from the tests
EXPOSE 22

# Start SSH server on container startup
CMD ["/usr/sbin/sshd", "-D"]
