#!/usr/bin/env bash
set -euo pipefail

VM_HOST="root@192.168.1.202"
VM_DIR="/opt/scanerr"
IMAGE_NAME="scanerr-app:latest"

echo "==> Building Docker image locally..."
docker build -t "$IMAGE_NAME" .

echo "==> Saving image as compressed tar..."
docker save "$IMAGE_NAME" | gzip > /tmp/scanerr-app.tar.gz

echo "==> Copying image to VM..."
scp /tmp/scanerr-app.tar.gz "${VM_HOST}:/tmp/scanerr-app.tar.gz"
rm /tmp/scanerr-app.tar.gz

echo "==> Loading image in VM..."
ssh "$VM_HOST" "gunzip -c /tmp/scanerr-app.tar.gz | docker load && rm /tmp/scanerr-app.tar.gz"

echo "==> Copying project files into VM..."
tar czf /tmp/scanerr-deploy.tar.gz docker-compose.yml postgres.conf scanerr.toml ranges.txt templates/ assets/ migrations/ GeoLite2-City.mmdb GeoLite2-ASN.mmdb
scp /tmp/scanerr-deploy.tar.gz "${VM_HOST}:/tmp/scanerr-deploy.tar.gz"
rm /tmp/scanerr-deploy.tar.gz
ssh "$VM_HOST" "mkdir -p $VM_DIR && cd $VM_DIR && tar xzf /tmp/scanerr-deploy.tar.gz && rm /tmp/scanerr-deploy.tar.gz && sed -i 's/127.0.0.1:8080/0.0.0.0:8080/' scanerr.toml"

echo "==> Restarting containers..."
ssh "$VM_HOST" "cd $VM_DIR && docker compose up -d --force-recreate --scale deepscan=4 --scale probe=4"

echo "==> Checking container status..."
ssh "$VM_HOST" "docker ps --filter 'name=scanerr' --format '{{.Names}}\t{{.Status}}'"

echo ""
echo "==> Done! Web UI at http://192.168.1.202:8080"
