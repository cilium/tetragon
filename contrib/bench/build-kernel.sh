#!/bin/bash

# This is example of user specific workload script

pushd /home/jolsa/bpf-next-1/tools/perf/

bash -c 'make clean; make -j 16'  > /dev/null 2>&1

popd
