#!/bin/sh
# Elasticsearch + Kibana Auto-Setup
# This runs automatically when phase 1 starts, creating index templates and data views
# so the user never has to manually configure anything.

set -e

ES_URL="http://elasticsearch:9200"
KB_URL="http://kibana:5601"

echo "============================================"
echo "  ContainerSentry Auto-Setup"
echo "============================================"

# ── Step 1: Wait for Elasticsearch ───────────────────────
echo ""
echo "[1/4] Waiting for Elasticsearch..."
until curl -sf "$ES_URL/_cluster/health" > /dev/null 2>&1; do
  printf "."
  sleep 3
done
echo " READY"

# ── Step 2: Create Index Templates ───────────────────────
echo ""
echo "[2/4] Creating index templates..."

# Template for attack-logs-*
curl -s -X PUT "$ES_URL/_index_template/attack-logs-template" \
  -H "Content-Type: application/json" \
  -d '{
  "index_patterns": ["attack-logs-*"],
  "template": {
    "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
    "mappings": {
      "dynamic_templates": [{
        "strings_as_keyword": {
          "match_mapping_type": "string",
          "mapping": { "type": "keyword", "ignore_above": 512 }
        }
      }],
      "properties": {
        "@timestamp":     { "type": "date" },
        "attack_id":      { "type": "keyword" },
        "attack_name":    { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
        "technique":      { "type": "keyword" },
        "mitre_technique":{ "type": "keyword" },
        "status":         { "type": "keyword" },
        "severity":       { "type": "keyword" },
        "detail":         { "type": "text" },
        "analysis":       { "type": "text" },
        "raw_output":     { "type": "text", "index": false },
        "target":         { "type": "keyword" },
        "agent":          { "type": "keyword" },
        "source":         { "type": "keyword" }
      }
    }
  }
}' && echo "  ✓ attack-logs template" || echo "  ✗ attack-logs template (may already exist)"

# Template for falco-events-*
curl -s -X PUT "$ES_URL/_index_template/falco-events-template" \
  -H "Content-Type: application/json" \
  -d '{
  "index_patterns": ["falco-events-*"],
  "template": {
    "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
    "mappings": {
      "dynamic_templates": [{
        "strings_as_keyword": {
          "match_mapping_type": "string",
          "mapping": { "type": "keyword", "ignore_above": 512 }
        }
      }],
      "properties": {
        "@timestamp":     { "type": "date" },
        "rule":           { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
        "priority":       { "type": "keyword" },
        "output":         { "type": "text" },
        "source":         { "type": "keyword" },
        "hostname":       { "type": "keyword" },
        "container.id":   { "type": "keyword" },
        "container.name": { "type": "keyword" },
        "container.image":{ "type": "keyword" },
        "proc.name":      { "type": "keyword" },
        "proc.pid":       { "type": "long" },
        "proc.cmdline":   { "type": "text", "index": false },
        "evt.type":       { "type": "keyword" },
        "fd.name":        { "type": "keyword" },
        "user.name":      { "type": "keyword" },
        "tags":           { "type": "keyword" }
      }
    }
  }
}' && echo "  ✓ falco-events template" || echo "  ✗ falco-events template (may already exist)"

# ── Step 3: Wait for Kibana ────────────────────────────
echo ""
echo "[3/4] Waiting for Kibana..."
until curl -sf "$KB_URL/api/status" > /dev/null 2>&1; do
  printf "."
  sleep 5
done
# Extra wait for Kibana to fully initialize
sleep 10
echo " READY"

# ── Step 4: Create Kibana Data Views ──────────────────────
echo ""
echo "[4/4] Creating Kibana data views..."

# Helper function to create a data view
create_data_view() {
  local TITLE="$1"
  local NAME="$2"
  local RESPONSE
  RESPONSE=$(curl -s -X POST "$KB_URL/api/data_views/data_view" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "{\"data_view\":{\"title\":\"$TITLE\",\"name\":\"$NAME\",\"timeFieldName\":\"@timestamp\"}}" 2>&1)
  if echo "$RESPONSE" | grep -q '"id"'; then
    echo "  ✓ $NAME"
  elif echo "$RESPONSE" | grep -qi "already exists"; then
    echo "  ~ $NAME (already exists)"
  else
    echo "  ✗ $NAME ($RESPONSE)"
  fi
}

# Important: Set the default timefield for the data views first
curl -s -X PUT "$KB_URL/api/data_views/default_timefield" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{"timeFieldName": "@timestamp"}' > /dev/null 2>&1 || true

# Create data views (even though no indices exist yet — Kibana 8.12 allows this)
create_data_view "attack-logs-*" "Attack Logs"
create_data_view "falco-events-*" "Falco Events"

# Set "Attack Logs" as the default data view so Discover opens to it first
sleep 2

echo ""
echo "============================================"
echo "  Setup Complete!"
echo ""
echo "  Access your dashboards:"
echo "  Security Dashboard:  http://localhost:5000"
echo "  Kibana:              http://localhost:5601"
echo "  Web App:             http://localhost:8080"
echo "  Falcosidekick UI:    http://localhost:2802"
echo "  Elasticsearch API:   http://localhost:9200"
echo ""
echo "  Phase 2:"
echo "  docker compose --profile attack up -d attacker"
echo "============================================"
