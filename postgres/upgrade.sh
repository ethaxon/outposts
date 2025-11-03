#!/bin/bash
set -e

mkdir -p ./backups
cp -rf ./data "./backups/data-$(date +%s)"

rm -rf ./data-new
cp -rf ./data ./data-new

docker run --name pgauto -it --rm \
  --env-file ../.env \
  -e POSTGRES_USER=outposts \
  -e POSTGRES_DB=postgres \
	-v ./data-new:/var/lib/postgresql/data \
	-e PGAUTO_ONESHOT=yes \
	pgautoupgrade/pgautoupgrade:latest

(cd .. && docker compose down)
rm -r ./data
cp -r ./data-new ./data
chmod -R 777 ./data
