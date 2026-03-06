# Debian bookworm SSH server with opkssh + NSS JIT user provisioning.
#
# This Dockerfile demonstrates deploying the opkssh NSS module on a Debian
# system.  JIT users are synthesised from /etc/opk/auth_id at login time so
# that no pre-existing /etc/passwd entries are required.
#
# Build-time ARGs (all required):
#   OPKSSH_VERSION  — opkssh release tag, e.g. "0.13.0"
#
# Runtime volume mounts expected:
#   /etc/opk/auth_id    — principals file (PRINCIPAL IDENTITY_ATTR ISSUER)
#   /etc/opk/providers  — trusted OIDC providers (ISSUER CLIENT_ID EXPIRY)
#
# See nss/example/ for sample auth_id, providers, and nss.conf files.

# ------------------------------------------------------------------ #
# Stage 1: compile the NSS .so and daemon                             #
# ------------------------------------------------------------------ #
FROM golang:1.21-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/nss
COPY nss/ .
RUN make all

# ------------------------------------------------------------------ #
# Stage 2: SSH server with opkssh JIT provisioning                    #
# ------------------------------------------------------------------ #
FROM debian:bookworm-slim

ARG OPKSSH_VERSION=0.13.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        libpam-modules \
        libpam-runtime \
        libpam-modules-bin \
        libc6 \
        bash \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------ #
# Install opkssh binary                                                #
# ------------------------------------------------------------------ #
RUN curl -fsSL \
    "https://github.com/openpubkey/opkssh/releases/download/v${OPKSSH_VERSION}/opkssh-linux-amd64" \
    -o /usr/bin/opkssh \
    && chmod 755 /usr/bin/opkssh

# Dedicated user that runs opkssh verify (matches opkssh documentation).
RUN useradd --system --no-create-home --shell /sbin/nologin opksshuser

# ------------------------------------------------------------------ #
# Install NSS module and daemon                                        #
# ------------------------------------------------------------------ #
COPY --from=builder /build/nss/libnss_opkssh.so.2 \
    /usr/lib/x86_64-linux-gnu/libnss_opkssh.so.2
COPY --from=builder /build/nss/opkssh-nssd /usr/sbin/opkssh-nssd
RUN ldconfig

# ------------------------------------------------------------------ #
# opkssh configuration                                                 #
# ------------------------------------------------------------------ #
RUN mkdir -p /etc/opk

# providers and auth_id are mounted at runtime; create stubs so the
# daemon and opkssh verify can start without errors if volumes are
# absent during development.
RUN touch /etc/opk/auth_id /etc/opk/providers \
    && chown root:opksshuser /etc/opk/auth_id /etc/opk/providers \
    && chmod 640 /etc/opk/auth_id /etc/opk/providers

# NSS daemon config: UID range 100000-199999, shared GID 100000.
# Override by mounting a custom /etc/opk/nss.conf.
COPY nss/example/nss.conf /etc/opk/nss.conf
RUN sed -i \
      -e 's/^uid_min.*/uid_min     = 100000/' \
      -e 's/^uid_max.*/uid_max     = 199999/' \
      -e 's/^gid.*/gid         = 100000/'   \
      /etc/opk/nss.conf

# opkssh log file
RUN touch /var/log/opkssh.log \
    && chown root:opksshuser /var/log/opkssh.log \
    && chmod 660 /var/log/opkssh.log

# Stub config.yml so opkssh does not emit a "file not found" warning.
RUN touch /etc/opk/config.yml \
    && chown root:opksshuser /etc/opk/config.yml \
    && chmod 640 /etc/opk/config.yml

# ------------------------------------------------------------------ #
# NSS: synthesise passwd and shadow entries for JIT users             #
# ------------------------------------------------------------------ #
RUN sed -i 's/^\(passwd\s*:\s*files\)/\1 opkssh/' /etc/nsswitch.conf && \
    if grep -q '^shadow' /etc/nsswitch.conf; then \
        sed -i 's/^\(shadow\s*:\s*files\)/\1 opkssh/' /etc/nsswitch.conf; \
    else \
        echo 'shadow: files opkssh' >> /etc/nsswitch.conf; \
    fi

# ------------------------------------------------------------------ #
# PAM: auto-create home directories on first login                    #
# ------------------------------------------------------------------ #
# No changes to /etc/pam.d/sshd are needed.  The shadow NSS module
# provides synthetic entries so pam_unix.so returns PAM_SUCCESS for JIT
# users, and the standard common-account stack works as-is.
RUN echo "session optional pam_mkhomedir.so skel=/etc/skel umask=0022" \
    >> /etc/pam.d/common-session

# ------------------------------------------------------------------ #
# sshd configuration                                                   #
# ------------------------------------------------------------------ #
COPY nss/example/sshd_extra.conf /etc/ssh/sshd_config.d/opkssh.conf

# ------------------------------------------------------------------ #
# Entrypoint                                                           #
# ------------------------------------------------------------------ #
COPY nss/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
CMD ["/entrypoint.sh"]
