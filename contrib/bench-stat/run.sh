#!/bin/bash

#set -x

fio=
fio_load=load.fio
fio_rate=10000G
data=data-run
name=mine
time=10
tmp=tmp
label=untitled

# bench_reader config variables
bench_reader=
bench_reader_path=
bench_reader_options=

run_tetragon=
run_falco=

while test $# -gt 0; do
	case "$1" in
	--time)
		shift
		time="$1"
		;;
	--data)
		shift
		data="$1"
		;;
	--name)
		shift
		name="$1"
		;;
	--fio)
		fio=1
		;;
	--fio-load)
		shift
		fio_load="$1"
		;;
	--fio-rate)
		shift
		fio_rate="$1"
		;;
	--bench-reader)
		bench_reader=1
		;;
	--bench-reader-options)
		shift
		bench_reader_options="$1"
		;;
	--label)
		shift
		label="$1"
		;;
	--run-tetragon)
		shift
		run_tetragon="$1"
		;;
	--run-falco)
		shift
		run_falco="$1"
		;;
	*)
		echo "unknown ${1}"
		exit 1
	esac
	shift
done

file=${data}/${name}.perf

echo "Running ${name}"
echo "- time:         ${time}s"
echo "- output:       ${file}"
echo "- run_tetragon: ${run_tetragon}"
echo "- run_falco:    ${run_falco}"

mkdir -p ${data} ${tmp}
rm -f ${file}*

killall_load=
killall_agent=

if [ -n "${run_tetragon}" ]; then
	echo -n "- starting tetragon ... "
	${run_tetragon} > tetragon.out 2>&1 &
	killall_agent=tetragon
	sleep 5
	echo "OK"
fi

if [ -n "${run_falco}" ]; then
	echo -n "- starting falco ... "
	${run_falco} > falco.out 2>&1 &
	killall_agent=falco
	sleep 5
	echo "OK"
fi

if [ -n "${fio}" ]; then
	fio_out=${tmp}/${name}.fio
	echo "- fio ${fio_load} ${fio_rate} ${fio_out}"
	fio ${fio_load} --rate=${fio_rate} >${fio_out} 2>&1 &
	killall_load=fio
	sleep 5
fi

if [ -n "${bench_reader}" ]; then
	echo -n "- starting bench reader ${bench_reader_options} ... "
	${bench_reader_path} ${bench_reader_options} > /dev/null 2>&1 &
	killall_load=bench-reader
	sleep 5
	echo "OK"
fi

echo -n "- all up, running perf for ${time}s ... "

perf stat -e cycles -I 1000 -x, -o ${file} -a -- sleep ${time}

echo "OK"

if [ -n "${killall_load}" ]; then
	echo "- killing workload"
	killall ${killall_load}
fi

if [ -n "${killall_agent}" ]; then
	echo "- killing agent"
	killall ${killall_agent}
fi

# add label to the first line
sed -i "1s;^;${label}\n;" ${file}
