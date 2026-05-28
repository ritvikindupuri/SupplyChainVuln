#!/bin/bash
# PacketSentry - Elasticsearch + Kibana Auto-Setup

set -e

ES_URL="http://elasticsearch:9200"
KB_URL="http://kibana:5601"
ES_USER="${ELASTIC_USER:-elastic}"
ES_PASS="${ELASTIC_PASSWORD:-packetsentry}"

echo "[+] Waiting for Elasticsearch..."
until curl -s -u "$ES_USER:$ES_PASS" "$ES_URL/_cluster/health" > /dev/null 2>&1; do
  sleep 3
done
echo "[+] Elasticsearch is ready."

echo "[+] Setting kibana_system password..."
curl -s -u "$ES_USER:$ES_PASS" -X POST "$ES_URL/_security/user/kibana_system/_password" \
  -H "Content-Type: application/json" \
  -d "{\"password\": \"$ES_PASS\"}" | jq .
echo "[+] Kibana system password set."

echo "[+] Creating index template for packetsentry-alerts..."
curl -s -u "$ES_USER:$ES_PASS" -X PUT "$ES_URL/_index_template/packetsentry_alerts" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["packetsentry-alerts-*"],
    "template": {
      "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
      "mappings": {
        "properties": {
          "@timestamp":     { "type": "date" },
          "session":        { "type": "keyword" },
          "event_type":     { "type": "keyword" },
          "cycle_id":       { "type": "keyword" },
          "severity":       { "type": "keyword" },
          "protocol":       { "type": "keyword" },
          "src_ip":         { "type": "ip" },
          "src_port":       { "type": "integer" },
          "dst_ip":         { "type": "ip" },
          "dst_port":       { "type": "integer" },
          "packet_count":   { "type": "integer" },
          "alert_count":    { "type": "integer" },
          "threat_level":   { "type": "keyword" },
          "claude_analysis":{ "type": "text" },
          "attack_name":    { "type": "keyword" },
          "mitre_tactic":   { "type": "keyword" },
          "mitre_technique":{ "type": "keyword" },
          "remediation":    { "type": "text" },
          "confidence":     { "type": "float" },
          "thinking_blocks":{ "type": "text" },
          "tool_calls":     { "type": "text" },
          "raw_pcap_ref":   { "type": "keyword" }
        }
      }
    }
  }' | jq .

echo "[+] Creating index template for packetsentry-packets..."
curl -s -u "$ES_USER:$ES_PASS" -X PUT "$ES_URL/_index_template/packetsentry_packets" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["packetsentry-packets-*"],
    "template": {
      "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
      "mappings": {
        "properties": {
          "@timestamp":   { "type": "date" },
          "session":      { "type": "keyword" },
          "cycle":        { "type": "integer" },
          "frame_len":    { "type": "integer" },
          "ip_src":       { "type": "ip" },
          "ip_dst":       { "type": "ip" },
          "ip_proto":     { "type": "keyword" },
          "src_port":     { "type": "integer" },
          "dst_port":     { "type": "integer" },
          "protocol":     { "type": "keyword" },
          "info":         { "type": "text" }
        }
      }
    }
  }' | jq .

echo "[+] Creating index template for packetsentry-activity..."
curl -s -u "$ES_USER:$ES_PASS" -X PUT "$ES_URL/_index_template/packetsentry_activity" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["packetsentry-activity-*"],
    "template": {
      "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
      "mappings": {
        "properties": {
          "@timestamp":   { "type": "date" },
          "session":      { "type": "keyword" },
          "event_type":   { "type": "keyword" },
          "cycle_id":     { "type": "keyword" },
          "data":         { "type": "object", "enabled": true }
        }
      }
    }
  }' | jq .

echo "[+] Waiting for Kibana..."
until curl -s "$KB_URL/kibana/api/status" > /dev/null 2>&1; do
  sleep 3
done
echo "[+] Kibana is ready."

echo "[+] Creating Kibana data views..."
for pair in "packetsentry-alerts-*:PacketSentry Alerts" "packetsentry-packets-*:PacketSentry Packets" "packetsentry-activity-*:PacketSentry Activity"; do
  pattern="${pair%%:*}"
  name="${pair##*:}"
  echo "[+] Creating data view: $name ($pattern)"
  response=$(curl -s -u "$ES_USER:$ES_PASS" -X POST "$KB_URL/kibana/api/data_views/data_view" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "{\"data_view\":{\"title\":\"$pattern\",\"name\":\"$name\",\"timeFieldName\":\"@timestamp\"}}")
  echo "$response" | head -c 200
  echo ""
done

echo "[+] Setup complete."
