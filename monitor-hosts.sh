#!/usr/bin/env bash
# Check host count on remote DB and notify if above threshold
THRESHOLD=573
COUNT=$(ssh -o ConnectTimeout=5 root@192.168.1.202 \
  "docker compose -f /opt/scanerr/docker-compose.yml exec -T postgres psql -U scanerr -d scanerr -t -A -c 'SELECT COUNT(*) FROM hosts'" 2>/dev/null | tr -d '[:space:]')

if [ -n "$COUNT" ] && [ "$COUNT" -gt "$THRESHOLD" ] 2>/dev/null; then
  notify-send -u critical "scanerr" "Host count rose to $COUNT (was $THRESHOLD)"
  echo "$(date): hosts=$COUNT — notified"
else
  echo "$(date): hosts=${COUNT:-?} — below threshold"
fi
