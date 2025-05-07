#!/usr/bin/env sh

if [ "${OPKSSH_PLUGIN_U}" = "root" ] && [ "${OPKSSH_PLUGIN_EMAIL}" = "test-user2@zitadel.ch" ]; then
  echo "allow"
else
  echo "deny"
fi