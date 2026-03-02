# Installing in Transactional systems

Transactional systems (also Atomic, Immutable) are a Linux variant where direct modification of the root file system is not permitted even for the root user. Some examples of transactional systems are [SLE Micro](https://www.suse.com/products/micro/), [openSUSE Leap Micro](https://get.opensuse.org/leapmicro/6.2/), [opensuse MicroOS](https://get.opensuse.org/microos/), [Fedora silverblue](https://www.fedoraproject.org/atomic-desktops/silverblue/), [Fedora Coreos](https://www.fedoraproject.org/coreos/)
The installation of opkssh in these machines needs slight adjustments and this document details the process for openSUSE Leap Micro v6.2.

## openSUSE Leap Micro 6.2

- Enter shell
  ```bash
  sudo transactional-update shell
  ```
- Create necessary folders and data
  ```bash
  mkdir /opt/opkssh
  cd /tmp
  curl -LO https://raw.githubusercontent.com/openpubkey/opkssh/main/scripts/install-linux.sh
  chmod u+x install-linux.sh
  ```
- Setup necessary variables and install, we select `/opt` since this is not part of the snapshots and also considered as the locations for user installations
  ```bash
  export OPKSSH_INSTALL_DIR=/opt/opkssh
  ./install-linux.sh --no-home-policy
  ```
- Output should be similar to follows

    ```bash
    Bash version: 5.2
    Added opksshuser to group: opksshuser
    Downloading version latest of opkssh from https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-linux-amd64...
    opkssh                          100%[=====================================================>]  12.74M  11.0MB/s    in 1.2s    
    Installed opkssh to /opt/opkssh/opkssh
    SELinux detected. Configuring SELinux for opkssh
      Restoring context for /opt/opkssh/opkssh...
      Downloading TE-file
      Compiling SELinux module...
      Packaging module...
      Installing module...
    SELinux module installed successfully!
    Configuring opkssh:
    Running in chroot, ignoring command 'restart'
    Installation successful! Run 'opkssh' to use it.
    ```
  - Exit the shell and reboot
    ```bash
    exit
    sudo shutdown -r now
    ```
- After restart, setup the policies and providers as required. NOTE: For all the scripts use the absolute path of the instllation `/opt/opkssh/opkssh`
