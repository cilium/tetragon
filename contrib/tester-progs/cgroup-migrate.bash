#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

#
# This script is part of the cgroup testing framework.
# It creates a new cgroup, migrates current process to it, then
#   fork+execve a binary to generate execve events with the new
#   related cgroup information.
#
# It assumes callers have:
#  - mounted either a cgroupv2 or a cgroupv1 hierarchy
#  - callers will pass the right cgroup version and controller
#    to use.
#
# This test is a bash script since we want to easily fork and
# execve, bash performs this by default. It helps reduce
# possible cgroup race conditions that are mentioned
# here: https://lwn.net/Articles/807882/

#
# Usage:
#   cgroup-migrate.bash -m cgroup2 -c memory -n new_cgroup_1 /sys/fs/cgroup/new_cgroup_1
#   cgroup-migrate.bash -m cgroup2 -c memory -n new_cgroup_2 /sys/fs/cgroup/new_cgroup_1/new_cgroup_2/
#   cgroup-migrate.bash -m cgroup2 -c memory -n new_cgroup_3 /sys/fs/cgroup/new_cgroup_1/new_cgroup_2/new_cgroup_3/
#
#  Or
#
#   cgroup-migrate.bash -m cgroup1 -c memory -n new_cgroup_1 /sys/fs/cgroup/memory/new_cgroup_1
#   cgroup-migrate.bash -m cgroup1 -c memory -n new_cgroup_2 /sys/fs/cgroup/memory/new_cgroup_1/new_cgroup_2/
#   cgroup-migrate.bash -m cgroup1 -c memory -n new_cgroup_3 /sys/fs/cgroup/memory/new_cgroup_1/new_cgroup_2/new_cgroup_3/
#
# At the end of tests, the '/sys/fs/cgroup/new_cgroup_1/...' cgroups can be
#   safely removed.
#

PROGRAM="$(basename "$0")"
#default mode is cgroup2
MODE="cgroupv2"
CONTROLLER="memory"
CGROUP1_MAGIC="27e0eb"
CGROUP2_MAGIC="63677270"

error() {
	>&2 echo -e "Error: ${*}"
}

fatal() {
	>&2 echo -e "Fatal: ${*}, exiting"
	exit 1
}

usage() {
	echo >&2 "usage: $PROGRAM [-m cgroup2|cgroup1] [-c memory|pids] [-n new_cgroup] new_cgroup_full_path"
	exit 1
}

if [ "$(id -u)" -ne "0" ]; then
	fatal "must be root"
fi

while [[ $# > 0 ]] ; do
	case "$1" in
		-m | --mode)
			MODE="$2"
			shift 2
			;;
		-n | --new)
			NEW_CGROUP="$2"
			shift 2
			;;
		-c | --controller)
			CONTROLLER="$2"
			shift 2
			;;
		-h | --help) usage ;;
		--)
			shift
			break
			;;
		*)
			NEW_FULL_PATH="$1"
			shift
			break
			;;
	esac
done

if [[ $MODE != "cgroupv2" && $MODE != "cgroupv1" ]]; then
	error "parameter --mode value '${MODE}' not supported"
	usage
fi

if [[ $CONTROLLER != "memory" && $CONTROLLER != "pids" ]]; then
	error "parameter --controller '${CONTROLLER} value not supported (should be memory or pids for safety)"
	usage
fi

# This should be the name of new cgroup to create
if [[ -z $NEW_CGROUP ]]; then
	error "New Cgroup path was not specified"
	usage
fi

# This should be the full path of the new cgroup on the filesystem
if [[ -z $NEW_FULL_PATH ]]; then
	error "New Full Cgroup path was not specified"
	usage
fi

# Print old/current cgroup of the bash
print_old_cgroup() {
	if [[ $MODE == "cgroupv2" ]]; then
		cgrouppath="/sys/fs/cgroup$(cat /proc/self/cgroup | cut -d ':' -f 3)"
	else
		cgrouppath="/sys/fs/cgroup/${CONTROLLER}$(grep ${CONTROLLER} /proc/self/cgroup | cut -d ':' -f 3)"
	fi

	echo -e "Old Cgroup:\tcgroup.Path=$cgrouppath"
}

migrate_and_run() {
	mode=${1}
	ID=${2}
	fullpath=${3}

	# Migrate process now
	echo $$ >> ${fullpath}/cgroup.procs
	if [[ $? -ne 0 ]]; then
		fatal "failed to migrate current process to '${fullpath}"
	fi

	# Gather the new cgroup path
	if [[ ${mode} == "cgroupv2" ]]; then
		cgrouppath="/sys/fs/cgroup$(cat /proc/self/cgroup | cut -d ':' -f 3)"
	else
		cgrouppath="/sys/fs/cgroup/${CONTROLLER}$(grep ${CONTROLLER} /proc/self/cgroup | cut -d ':' -f 3)"
	fi

	echo -e "New Cgroup:\tcgroup.Path=$cgrouppath (1)"

	# We do unshare to ensure a fork+exec combination that will allow us
	# to have the process properly migrated to the right cgroup and minimize
	# cgroup migration race conditions
	unshare -f /bin/bash -c "/usr/bin/printf \"${ID}\n\""

	# Let's retry and avoid https://lwn.net/Articles/807882/
	echo -e "New Cgroup:\tcgroup.Path=$cgrouppath (2)"
	unshare -f /bin/bash -c "/usr/bin/printf \"${ID}\n\""
}

migrate_current_to_cgroupv1() {
	ID=${1}
	fullpath=${2}
	parent=$(dirname ${fullpath})
	magic=$(stat -f ${parent} -c "%t")

	# Ensure that we are operating on a cgroupv1 filesystem
	if [[ "${magic}" != "${CGROUP1_MAGIC}" ]]; then
		fatal "cgroup path '${parent}' is not on a cgroupv1 filesystem"
	fi

	# Inside current cgroup allow to migrate processes to child cgroups
	old=$(cat ${parent}/cgroup.clone_children)
	if [[ "${clone}" == "0" ]]; then
		echo "1" > "${parent}/cgroup.clone_children"
		if [[ $? -ne 0 ]]; then
			fatal "failed to allow '${parent}/cgroup.clone_children'"
		fi
	fi

	# Create the child cgroup
	mkdir ${fullpath}
	if [[ $? -ne 0 ]]; then
		fatal "failed to create cgroup ${fullpath}"
	fi

	# Migrate current process to child cgroup, then fork and execve
	migrate_and_run ${MODE} ${ID} ${fullpath}
}

migrate_current_to_cgroupv2() {
	ID=${1}
	fullpath=${2}
	parent=$(dirname ${fullpath})
	magic=$(stat -f ${parent} -c "%t")

	# Ensure that we are operating on a cgroupv2 filesystem
	if [[ "${magic}" != "${CGROUP2_MAGIC}" ]]; then
		fatal "cgroup path '${parent}' is not on a cgroupv2 filesystem"
	fi

	# Allow controllers in sub trees (subcgroups) for next round, then migrate after
	# to: https://elixir.bootlin.com/linux/v6.0.8/source/kernel/cgroup/cgroup.c#L2648
	child=$(grep ${CONTROLLER} ${parent}/cgroup.subtree_control)
	if [[ -z $child ]]; then
		echo "+${CONTROLLER}" >> "${parent}/cgroup.subtree_control"
		if [[ $? -ne 0 ]]; then
			fatal "failed to add '${CONTROLLER}' controller to subtree_control of '${parent}"
		fi
		echo "+pids" >> "${parent}/cgroup.subtree_control"
	fi

	# Create the child cgroup
	mkdir ${fullpath}
	if [[ $? -ne 0 ]]; then
		fatal "failed to create cgroup ${fullpath}"
	fi

	# Inside current cgroup add the controllers that should be used by this
	# cgroup but also to allow sub cgroups to inherit this same controllers
	# in the next round. See the cgroup.subtree_control above.
	current=$(grep ${CONTROLLER} ${fullpath}/cgroup.controllers)
	if [[ -z $current ]]; then
		echo "+${CONTROLLER}" >> "${fullpath}/cgroup.controllers"
		if [[ $? -ne 0 ]]; then
			fatal "failed to add '${CONTROLLER}' controller to '${fullpath}"
		fi
		echo "+pids" >> "${fullpath}/cgroup.controllers"
	fi

	# Migrate current process to child cgroup, then fork and execve
	migrate_and_run ${MODE} ${ID} ${fullpath}
}

# Let's first print current or old cgroup of the bash
print_old_cgroup

if [[ $MODE == "cgroupv2" ]]; then
	migrate_current_to_cgroupv2 $NEW_CGROUP $NEW_FULL_PATH
else
	migrate_current_to_cgroupv1 $NEW_CGROUP $NEW_FULL_PATH
fi

exit 0