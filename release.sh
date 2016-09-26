#!/bin/bash

set -e

if [ "$(uname)" == "Darwin" ]; then
    if ! which gsed; then
        echo gsed missing
        exit 1
    fi
    SED=gsed
else
    SED=sed
fi

if [ $# -lt 2 ] || ( [ ! $1 = 'android' ] && [ ! $1 = 'ios' ] );
then
    echo "Invalid or no arguments provided."
    cat <<EOF
Usage: ./prepare.sh (android | ios) VERSION

Prepares a new Cordova app release.

positional arguments:
  (android | ios)         Platform to release for
  VERSION                 Version number to release
EOF
    exit 1
fi

if [ ! -z "`git status -s | grep -v ^??`" ]; then  ## ?? = untracked files
    echo "You have uncommited changes. Please revert/stash them."
    exit 1
fi

$SED -i 's/<widget\(.*\)version="[0-9.]\+"/<widget\1version="'$2'"/' \
    www/config.xml

git commit -S -am"bump version for release $2"

$SED -i 's|WEBFILES_BRANCH=${WEBFILES_BRANCH##refs/heads/}|WEBFILES_BRANCH="'$1-v$2'"|' prepare.sh

git commit -S -am"update prepare.sh for release $2"
git tag -s -m "release $2 for $1" $1-v$2
git reset --hard HEAD^  # revert the release.sh change for the main branch

if [ "$1" == "ios" ]; then
    git reset --hard HEAD^  # revert the version bump for ios (master contains the Android version)
fi

cd webfiles
git tag -s -m "release $2 for $1" $1-v$2
cd ..

echo "Update and tagging done. Now please push this repo and webfiles/ with --tags."
