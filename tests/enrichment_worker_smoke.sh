#!/usr/bin/env bash
set -euo pipefail
workers="$(realpath "${1:?worker directory}")"
fixture="$(realpath "${2:?source-backed ELF fixture}")"
report="$(mktemp -d /tmp/indago-enrichment-workers.XXXXXX)"
timeout --kill-after=3s 30s "$workers/capa" --backend vivisect --format elf --json --color never --quiet -- "$fixture" > "$report/capa.json" 2> "$report/capa.stderr.log"
jq -e '.meta.flavor=="static" and .meta.analysis.format=="elf" and .meta.version=="9.4.0"' "$report/capa.json" >/dev/null
timeout --kill-after=3s 30s "$workers/floss" --only static --language none --json --color never --quiet -- "$fixture" > "$report/floss.json" 2> "$report/floss.stderr.log"
jq -e '.strings.static_strings|length>0' "$report/floss.json" >/dev/null
jq -nc --arg report "$report" '{status:"passed",report:$report,target_executed:false}'
