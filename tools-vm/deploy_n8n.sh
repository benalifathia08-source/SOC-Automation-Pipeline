#!/bin/bash
# Deploy or update n8n on the tools VM (run with sudo from the folder holding docker-compose.yml).
# Safe to re-run: the encryption key is generated once and never printed or overwritten.
#   Back up the key yourself: sudo cat /opt/soc-pipeline/.env  (without it, saved credentials are lost)
set -e
DIR=/opt/soc-pipeline
SRC=$(cd "$(dirname "$0")" && pwd)

install -d -m 0750 "$DIR"
install -m 0644 "$SRC/docker-compose.yml" "$DIR/docker-compose.yml"

if [ ! -s "$DIR/.env" ]; then
    umask 077
    echo "N8N_ENCRYPTION_KEY=$(openssl rand -hex 32)" > "$DIR/.env"
    echo "generated a new n8n encryption key in $DIR/.env (not shown)"
fi
chmod 600 "$DIR/.env"

cd "$DIR"
docker compose pull -q
docker compose up -d
docker compose ps

echo "== waiting for n8n"
for i in $(seq 1 60); do
    if curl -fsS http://192.168.145.20:5678/healthz > /dev/null 2>&1; then
        echo "n8n is up: http://192.168.145.20:5678"
        docker exec n8n n8n --version
        exit 0
    fi
    sleep 2
done
echo "n8n did not answer within 2 minutes; recent logs:"
docker compose logs --tail 40 n8n
exit 1
