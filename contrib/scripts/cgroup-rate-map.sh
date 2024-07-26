#!/bin/sh

map=$1
dump=

if [ -f ${map} ]; then
  dump="pinned ${map}"
else
  dump="id ${map}"
fi

bpftool map dump ${dump} | \
jq .[] | jq -r '["id","cpu","curr","prev","rate","time","throttled"],[.key.id] + (.values[] | [.cpu] + (.value | [.curr,.prev,.rate,.time,.throttled])) | @tsv'
