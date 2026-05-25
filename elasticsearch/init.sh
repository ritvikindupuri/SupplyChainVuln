#!/bin/bash
# Elasticsearch initialization script
# This creates index templates for our attack and falco logs

echo "Waiting for Elasticsearch to be ready..."
until curl -s http://localhost:9200/_cluster/health | grep -q '"status"'; do
  sleep 2
done
echo "Elasticsearch is ready."

# Index template for attack logs
curl -X PUT "http://localhost:9200/_index_template/attack-logs-template" -H "Content-Type: application/json" -d '{
  "index_patterns": ["attack-logs-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "dynamic_templates": [
        {
          "strings_as_keyword": {
            "match_mapping_type": "string",
            "mapping": {
              "type": "keyword",
              "ignore_above": 512
            }
          }
        }
      ],
      "properties": {
        "@timestamp": { "type": "date" },
        "attack_id": { "type": "keyword" },
        "attack_name": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
        "technique": { "type": "keyword" },
        "mitre_technique": { "type": "keyword" },
        "status": { "type": "keyword" },
        "detail": { "type": "text" },
        "analysis": { "type": "text" },
        "raw_output": { "type": "text", "index": false },
        "target": { "type": "keyword" },
        "agent": { "type": "keyword" },
        "source": { "type": "keyword" }
      }
    }
  }
}'

# Index template for Falco events
curl -X PUT "http://localhost:9200/_index_template/falco-events-template" -H "Content-Type: application/json" -d '{
  "index_patterns": ["falco-events-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "dynamic_templates": [
        {
          "strings_as_keyword": {
            "match_mapping_type": "string",
            "mapping": {
              "type": "keyword",
              "ignore_above": 512
            }
          }
        }
      ],
      "properties": {
        "@timestamp": { "type": "date" },
        "rule": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
        "priority": { "type": "keyword" },
        "output": { "type": "text" },
        "source": { "type": "keyword" },
        "hostname": { "type": "keyword" },
        "container": {
          "properties": {
            "id": { "type": "keyword" },
            "name": { "type": "keyword" },
            "image": { "type": "keyword" }
          }
        },
        "proc": {
          "properties": {
            "name": { "type": "keyword" },
            "pid": { "type": "long" },
            "cmdline": { "type": "text", "index": false },
            "exepath": { "type": "keyword" }
          }
        },
        "fd": {
          "properties": {
            "name": { "type": "keyword" },
            "num": { "type": "long" }
          }
        },
        "evt": {
          "properties": {
            "type": { "type": "keyword" },
            "time": { "type": "date" },
            "dir": { "type": "keyword" }
          }
        },
        "user": {
          "properties": {
            "name": { "type": "keyword" },
            "uid": { "type": "long" }
          }
        },
        "tags": { "type": "keyword" }
      }
    }
  }
}'

echo "Index templates created successfully."

# Create Kibana data views
echo "Setting up Kibana data views..."
KIBANA_URL="http://kibana:5601"

# Wait for Kibana
until curl -s "$KIBANA_URL/api/status" 2>/dev/null | grep -q "green"; do
  sleep 3
done

# Create data view for attack logs
curl -X POST "$KIBANA_URL/api/data_views/data_view" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d '{
  "data_view": {
    "title": "attack-logs-*",
    "name": "Attack Logs",
    "timeFieldName": "@timestamp"
  }
}'

# Create data view for Falco events
curl -X POST "$KIBANA_URL/api/data_views/data_view" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d '{
  "data_view": {
    "title": "falco-events-*",
    "name": "Falco Events",
    "timeFieldName": "@timestamp"
  }
}'

echo "Kibana data views created."

# Import sample dashboard
curl -X POST "$KIBANA_URL/api/saved_objects/_import" -H "kbn-xsrf: true" --form file=@/dev/null 2>/dev/null || true

echo "Elasticsearch initialization complete."
