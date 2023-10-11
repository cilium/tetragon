#!/bin/bash

data=data-run
tmp=tmp
paste=
plot=
gp_plot=gnuplot.plot
gp_file=gnuplot.dat

while test $# -gt 0; do
	case "$1" in
	--data)
		shift
		data="$1"
		;;
	*)
		echo "unknown ${1}"
		exit 1
	esac
	shift
done

data=`realpath ${data}`
tmp=`realpath ${tmp}`
gp_file=`realpath ${gp_file}`
gp_plot=`realpath ${gp_plot}`

cat > ${gp_plot} <<EOF
set grid
set title 'stats'
set xlabel 'time'
plot \\
EOF

pushd ${data}

pwd

col=2
for input in `ls * | sort`; do
	# get data numbers
	sed '1,3d' ${input} | awk -F, '{ print $2 }' > ${tmp}/${input}.awk
	sed '1,3d' ${input} | awk -F. '{ print $1 }' > ${tmp}/time.awk
	paste="${paste} ${tmp}/${input}.awk"

	# get data title
	title=$(head -1 ${input})

	# get data plot
	echo "'${gp_file}' u 1:${col} w lp t '${title}', \\" >> ${gp_plot}
	col=$((col+1))
done

popd

# last empty line
echo >> ${gp_plot}

paste -d' ' ${tmp}/time.awk ${paste} > ${gp_file}
