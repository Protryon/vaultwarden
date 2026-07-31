#!/bin/bash
set -ex
here=$(realpath $(dirname "$0"))
cd "$here"

if [ -z ${1+x} ] ; then
    echo "missing tag"
    exit 1
fi

export TAG=$1

# Always target x86_64 (linux/amd64), regardless of host architecture (e.g. Apple
# Silicon), via buildx + QEMU emulation. Building and pushing in one step avoids
# needing to load a foreign-arch image into the local docker daemon.
docker buildx build --platform linux/amd64 -t protryon/vaultwarden:$TAG -f ./Dockerfile . --push

echo "Uploaded image protryon/vaultwarden:$TAG"
