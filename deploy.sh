#!/bin/sh
# deploy.sh - update this checkout and rebuild, recording the commit that runs.
#
#   ./deploy.sh            git pull, then build and start every service
#   ./deploy.sh mgmt-api   only the named services
#
# OW_BUILD_COMMIT tells the console which commit it runs (Application → service → Code shows the findings of
# exactly that commit); docker-compose.yml passes it to the mgmt-api container.
set -e
cd "$(dirname "$0")"
git pull --ff-only
OW_BUILD_COMMIT="$(git rev-parse HEAD)"
export OW_BUILD_COMMIT
echo "Deploying commit $OW_BUILD_COMMIT"
docker compose build "$@"
docker compose up -d "$@"
