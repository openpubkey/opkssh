#!/usr/bin/env sh

if [ "$1" = "root" ] && [ "$2" = "test-user2@zitadel.ch" ]; then
  echo "allowed"
else
  echo "reject"
fi