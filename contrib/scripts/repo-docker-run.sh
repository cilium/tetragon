#!/usr/bin/env bash
#
# Running things that use the git command in a container might result in issues when using bare git
# directories, worktrees, or repositories cloned with --shared. This script aims to address that.
#
# See: https://github.com/buildroot/buildroot/blob/master/utils/docker-run


DIR=$(dirname "${0}")
MAIN_DIR=$(readlink -f "${DIR}/..")
if [ -L "${MAIN_DIR}/.git/config" ]; then
    # Support git-new-workdir
    GIT_DIR="$(dirname "$(realpath "${MAIN_DIR}/.git/config")")"
else
    # Support git-worktree
    GIT_DIR="$(cd "${MAIN_DIR}" && git rev-parse --no-flags --git-common-dir)"
fi

declare -a mountpoints=(
    "${MAIN_DIR}"
)

# Empty GIT_DIR means that we are not in a workdir, *and* git is too old
# to know about worktrees, so we're not in a worktree either. So it means
# we're in the main git working copy, and thus we don't need to mount the
# .git directory.
if [ "${GIT_DIR}" ]; then
    # GIT_DIR in the main working copy (when git supports worktrees) will
    # be just '.git', but 'docker run' needs an absolute path. If it is
    # not absolute, GIT_DIR is relative to MAIN_DIR. If it's an absolute
    # path already (in a wordir), then that's a noop.
    GIT_DIR="$(cd "${MAIN_DIR}"; readlink -e "${GIT_DIR}")"
    mountpoints+=( "${GIT_DIR}" )

    # 'repo' stores .git/objects separately.
    if [ -L "${GIT_DIR}/objects" ]; then
        # GITDIR is already an absolute path, but for symetry
        # with the above, keep the same cd+readlink construct.
        OBJECTS_DIR="$(cd "${MAIN_DIR}"; readlink -e "${GIT_DIR}/objects")"
        mountpoints+=( "${OBJECTS_DIR}" )
    fi
fi

declare -a docker_opts=(
    --rm
    --user "$(id -u):$(id -g)"
)

# shellcheck disable=SC2013 # can't use while-read because of the assignment
for dir in $(printf '%s\n' "${mountpoints[@]}" |LC_ALL=C sort -u); do
    docker_opts+=( --mount "type=bind,src=${dir},dst=${dir}" )
done

docker run "${docker_opts[@]}" "${@}"
