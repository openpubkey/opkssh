# OPKSSH on AWS EC2 Setup

AWS EC2 Instance Connect lets you connect to an instance from the browser but overrides sshd in a way that blocks opkssh. Below are two workarounds to get opkssh working on EC2.

Install opkssh for server via installation script provided in [README.md](https://github.com/openpubkey/opkssh?tab=readme-ov-file#installing-on-a-server)

After installation, you will still not able to ssh to the server using `opkssh` because of the following reason.

### Why opkssh doesn’t work on AWS EC2

[EC2 Instance Connect](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-set-up.html) creates a temporary SSH key for browser-based login. To do that it overrides sshd’s `AuthorizedKeysCommand` with `eic_run_authorized_keys`.

sshd only supports one `AuthorizedKeysCommand`, so when that is set to Instance Connect, opkssh cannot use it for authentication.

## Option 1: Disable AWS EC2 Instance Connect

In case you don't need AWS EC2 Instance Connect, you can disable it in order to make opkssh work. Follow the steps below to disable it.

**1. Remove EC2 drop-in that overrides the keys command**

```bash
sudo mv /usr/lib/systemd/system/ssh.service.d/ec2-instance-connect.conf /usr/lib/systemd/system/ssh.service.d/ec2-instance-connect.conf.bak
```

**2. Reload systemd to reflect the change**

```bash
sudo systemctl daemon-reload
```

**3. Make sure ssh.service is directly enabled (not socket-activated)**

```bash
sudo systemctl disable ssh.socket
sudo systemctl enable ssh.service
```

**4. Restart the SSH server cleanly**

```bash
sudo systemctl restart ssh
```

## Option 2: Custom bash script to override sshd authentication

You can create a custom bash script that calls `opkssh` and then calls `aws instance connect` as fallback and use it to override sshd authentication.

Here are the steps to create the custom bash script:

**1. Disable the EC2 Instance Connect**

```bash
# Backup the ec2-instance-connect.conf file
sudo mv /usr/lib/systemd/system/ssh.service.d/ec2-instance-connect.conf /usr/lib/systemd/system/ssh.service.d/ec2-instance-connect.conf.bak


# Reload systemd and restart ssh
sudo systemctl daemon-reload
sudo systemctl restart ssh
```

**2. Create the custom bash script** at `/usr/local/bin/akcmd-opkssh-aws.sh` for override sshd authentication:

```bash
#!/usr/bin/env bash
set -euo pipefail

USER="$1"
KEY="$2"
TYPE="$3"
FINGERPRINT="$4"

# 1) Try opkssh for authentication
if /usr/local/bin/opkssh verify "$USER" "$KEY" "$TYPE"; then
    exit 0
fi

# 2) Fallback to EC2 Instance Connect
exec /usr/share/ec2-instance-connect/eic_run_authorized_keys "$USER" "$FINGERPRINT"
```

Make the script executable and set ownership:

```bash
sudo chmod 750 /usr/local/bin/akcmd-opkssh-aws.sh
sudo chown root:opksshuser /usr/local/bin/akcmd-opkssh-aws.sh
```

**3. Back up the existing opk-ssh config (optional):**

```bash
sudo mv /etc/ssh/sshd_config.d/60-opk-ssh.conf /etc/ssh/sshd_config.d/60-opk-ssh.conf.bak
```

**4. Create** `/etc/ssh/sshd_config.d/60-opk-ssh.conf` with:

```
AuthorizedKeysCommand /usr/local/bin/akcmd-opkssh-aws.sh %u %k %t %f
AuthorizedKeysCommandUser opksshuser
```

**5. Restart the SSH server cleanly**

```bash
sudo systemctl daemon-reload

sudo systemctl restart ssh
```
