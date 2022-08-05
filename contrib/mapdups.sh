#!/bin/bash

# mapdups.sh
#
# This helper script is useful for parsing a bpftool map dump and determining whether or
# not duplicate maps are loaded (as indicated by their map name). It's not a perfect
# solution, but is helpful for rough debugging locally when something is not working right
# in Tetragon.
#
# When run on a file containing bpftool map output, the result will be a list of map names
# and their respective counts, sorted by count. Numbers higher than 1 are considered
# suspicious unless the map is OK to be duplicated (e.g. a "*heap" map in Tetragon.)
#
# Example usage:
#
# sudo bpftool map > dump.maps
# ./mapdups.sh dump.maps

if [ ! -f "$1" ]; then
    echo "Usage: mapdups.sh <MAPS_DUMP_PATH>" 1>&2
    exit 1
fi

awk '/^[0-9]+:/ { if ($3 == "name") { print $4 } }' "$1" | sort | uniq -c | sort

