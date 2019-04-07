#!/bin/bash

here=$(dirname "$0")
test -n "$here" -a -d "$here" || (echo "Cannot determine build dir. FIXME!" && exit 1)

. "$here"/../../base.sh # functions we use below (fail, et al)

if [ ! -z "$1" ]; then
    REV="$1"
else
    fail "Please specify a release tag or branch to build (eg: master or 4.0.0, etc)"
fi

if [ ! -d 'contrib' ]; then
    fail "Please run this script form the top-level Electron Cash git directory"
fi

pushd .

docker_version=`docker --version`

if [ "$?" != 0 ]; then
    echo ''
    echo "Please install docker by issuing the following commands (assuming you are on Ubuntu):"
    echo ''
    echo '$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -'
    echo '$ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"'
    echo '$ sudo apt-get update'
    echo '$ sudo apt-get install -y docker-ce'
    echo ''
    fail "Docker is required to build for Windows"
fi

set -e

info "Using docker: $docker_version"

SUDO=""  # on macOS (and others?) we don't do sudo for the docker commands ...
if [ $(uname) = "Linux" ]; then
    # .. on Linux we do
    SUDO="sudo"
fi

info "Creating docker image ..."
$SUDO docker build --no-cache -t electroncash-appimage-builder-img contrib/build-linux/appimage \
    || fail "Failed to create docker image"

# This is the place where we checkout and put the exact revision we want to work
# on. Docker will run mapping this directory to /opt/electroncash
# which inside wine will look lik c:\electroncash
FRESH_CLONE=`pwd`/contrib/build-linux/fresh_clone
FRESH_CLONE_DIR=$FRESH_CLONE/$GIT_DIR_NAME

(
    $SUDO rm -fr $FRESH_CLONE && \
        mkdir -p $FRESH_CLONE && \
        cd $FRESH_CLONE  && \
        git clone $GIT_REPO && \
        cd $GIT_DIR_NAME && \
        git checkout $REV
) || fail "Could not create a fresh clone from git"

(
    $SUDO docker run -it \
    --name electroncash-appimage-builder-cont \
    -v $FRESH_CLONE_DIR:/opt/electroncash \
    --rm \
    --workdir /opt/electroncash/contrib/build-linux/appimage \
    electroncash-appimage-builder-img \
    ./_build.sh $REV
) || fail "Build inside docker container failed"

popd

info "Copying .exe files out of our build directory ..."
mkdir -p contrib/build-wine/dist
files=$FRESH_CLONE_DIR/contrib/build-wine/dist/*.exe
for f in $files; do
    bn=`basename $f`
    cp -fpv $f contrib/build-wine/dist/$bn || fail "Failed to copy $bn"
    touch contrib/build-wine/dist/$bn || fail "Failed to update timestamp on $bn"
done

info "Removing $FRESH_CLONE ..."
$SUDO rm -fr $FRESH_CLONE

echo ""
info "Done. Built .exe files have been placed in contrib/build-wine/dist"
