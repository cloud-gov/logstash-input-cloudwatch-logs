#!/usr/bin/env bash

LOGSTASH_PLUGIN=$1
if [[ -z "$LOGSTASH_PLUGIN" ]]; then
  echo "Path to logstash plugin required as first argument"
  exit 1
fi

GEM_NAME="logstash-input-cloudwatch_logs"
VERSION=$(grep 's.version' logstash-input-cloudwatch_logs.gemspec | awk '{print $3}' | tr -d "'")

jruby -S gem build "$GEM_NAME.gemspec"
$LOGSTASH_PLUGIN install "$GEM_NAME-$VERSION.gem"
$LOGSTASH_PLUGIN prepare-offline-pack --output "$GEM_NAME-$VERSION.zip" "$GEM_NAME"
