#!/usr/bin/env bash

usage () {
    echo "This tool scans the provided directory for Dockerfiles and compares the"
    echo "images sha256 digests specified with the multi-architecture ones that"
    echo "might be available in order to improve compatibility."
    echo ""
    echo "Usage:"
    echo -e "\t$0 (directory or files)"
    echo ""
    echo "Examples:"
    echo -e "\t$0 ."
    echo -e "\t$0 \$(git rev-parse --show-toplevel)"
    echo -e "\tgit diff --name-only main | xargs $0"
    echo ""
    echo "Return value:"
    echo -e "\tOn overall success, the script returns 0. On error of any image"
    echo -e "\tdigest, the script returns 1. A warning is not considered as"
    echo -e "\tan error."
}

if [ -z "$1" ]; then
    usage
    exit 1
fi

RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
NC=$(tput sgr0)

images=$(grep -n -r --include='*[dD]ockerfile*' 'FROM' "$@" | grep -E '\b\S+@\S+\b')

exit_code=0

if ! command -v "crane" >/dev/null 2>&1; then
    echo "crane could not be found, please install crane: https://github.com/google/go-containerregistry/tree/main/cmd/crane."
    exit 1
fi

IFS=$'\n'
for image_meta in $images; do
    image=$(echo $image_meta | grep -Eo '\b\S+@\S+\b')
    line=$(echo $image_meta | cut -d':' -f2)
    file=$(echo $image_meta | cut -d':' -f1)
    echo -e "Checking ${BLUE}$image${NC}"
    echo -e "From file $file, line $line"

    name=$(echo $image | cut -d'@' -f1)
    sha=$(echo $image | cut -d'@' -f2)

    multiarch_sha=$(crane digest --platform all $name)
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}warning${NC}: retrieving the desired sha256 digest failed, please verify that tag of image '$name' exists and is valid.\n"
        continue
    fi

    if [ "$sha" == "$multiarch_sha" ]; then
        echo -e "${GREEN}success${NC}: sha256 digests are matching\n"
    else
        # when sha256 are not matching, there could be two main reasons:
        #   - the image was updated and the last version of that tag has a new digest
        #   - this is the sha256 of an arch-specific version while a multi-arch version exists
        # to determine this, we need the mediaType available in the manifest

        # this counts as an image pull and can be subject to rate limit
        image_manifest=$(crane manifest $image)
        if [ $? -ne 0 ]; then
            echo "${RED}error${NC}: manifest pull of $image failed"
            exit_code=1
            continue
        fi
        local_type=$(echo $image_manifest | jq -r '.mediaType')
        echo -e "\tlocal mediaType: $local_type"
        echo $local_type | grep -q list
        repo=$?

        # this counts as an image pull and can be subject to rate limit
        name_manifest=$(crane manifest $name)
        if [ $? -ne 0 ]; then
            echo "${RED}error${NC}: manifest pull of $name failed"
            exit_code=1
            continue
        fi
        remote_type=$(echo $name_manifest | jq -r '.mediaType')
        echo -e "\tlast mediaType:  $remote_type"
        echo $remote_type | grep -q list
        last=$?

        if [ "$repo" != "$last" ]; then
            # It could be a false positive if the image tag was recently updated to support multi-arch
            echo -e "${RED}error${NC}: sha256 digests mismatch, multi-arch version available for that tag\n\twant: $multiarch_sha\n\tgot:  $sha\n"
            exit_code=1
        else
            echo -e "${YELLOW}warning${NC}: sha256 digests mismatch, digest could be updated for that tag\n\twant: $multiarch_sha\n\tgot:  $sha\n"
        fi
    fi
done

exit $exit_code

