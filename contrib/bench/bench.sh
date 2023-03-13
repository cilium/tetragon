#!/bin/bash

FINAL=results.csv
BENCH_TETRAGON="$(realpath ${BENCH_TETRAGON:-./tetragon-bench})"
BENCH_TETRA="$(realpath ${BENCH_TETRA:-./tetra})"

workload()
{
	name=$1
	script=$2
	dir=$3
	opts=

	opts="${opts} -e cycles,cycles:u,cycles:k,instructions:u,instructions:k,duration_time"
	opts="${opts} -a -r 3"
	opts="${opts} -x, -o ${dir}/perf.stat.${name}.csv"

	perf stat ${opts} -- ${script}
}

bench()
{
	name=$1
	yaml=$2
	baseline=$3
	rbsize=$4
	store=$5

	opts="-crd ${yaml}"
	opts="${opts} -name ${name} -csv tetragon.stat.${name}.csv"

	if [ "${baseline}" = "1" ]; then
		opts="${opts} -baseline"
	fi

	if [ "${rbsize}" != "0" ]; then
		opts="${opts} -rb-size ${rbsize}"
	fi

	if [ "${rbsize}" != "0" ]; then
		opts="${opts} -store"
	fi

	printf "%-30s [ %s ]\n" "${name}" "${opts}"

	${BENCH_TETRAGON} ${opts} -- ${SELF} workload ${name} ${SCRIPT} ${DIR} > tetragon.output.${name} 2>&1

	cat tetragon.stat.${name}.csv >> ${FINAL}
	cat perf.stat.${name}.csv >> ${FINAL}
	echo >> ${FINAL}
}

prepare()
{
	if [ -d ${DIR}.old ]; then
		rm -rf ${DIR}.old
	fi
	if [ -d ${DIR} ]; then
		mv ${DIR} ${DIR}.old
	fi
	mkdir -p ${DIR}
}

# Use "BENCH_VERBOSE=1" to debug this script
case "${BENCH_VERBOSE}" in
*1*)
	set -x
	;;
esac

if [ "$1" = "workload" ]; then
        workload $2 $3 $4
        exit 0
fi

SELF=$(realpath $0)
SCRIPT=$(realpath $1)
DIR=$(realpath ${2:-./bench-results})

prepare ${DIR}

pushd ${DIR} >/dev/null

echo > ${FINAL}

${BENCH_TETRA} tracingpolicy generate all-syscalls --match-binary="/krava" > sc.yaml
${BENCH_TETRA} tracingpolicy generate empty > empty.yaml

echo "scipt: ${SCRIPT} "
echo "dir:   ${DIR} "
echo

bench baseline empty.yaml 1 0 0

bench base-sensor empty.yaml 0 0 0
bench base-sensor-rb1M empty.yaml 0 1048576 0
bench base-sensor-store empty.yaml 0 0 1
bench base-sensor-store-rb1M empty.yaml 0 1048576 1

bench syscalls-filtered sc.yaml 0 0 0
bench syscalls-filtered-rb1M sc.yaml 0 1048576 0
bench syscalls-filtered-store sc.yaml 0 0 1
bench syscalls-filtered-store-rb1M sc.yaml 0 1048576 1

popd >/dev/null
