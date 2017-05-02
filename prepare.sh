#!/bin/bash

set -e

# Prevent cordova prompting us to opt-in to telemetry on first use
cordova telemetry off >/dev/null 2>&1

WEBFILES_REPO="https://github.com/greenaddress/GreenAddressWebFiles.git"
WEBFILES_BRANCH=$(git symbolic-ref HEAD || echo $TRAVIS_BRANCH)
WEBFILES_BRANCH=${WEBFILES_BRANCH##refs/heads/}

while [ $# -gt 0 ]; do
key="$1"

case $key in
    -h|--help)
    HELP=1
    ;;
    -r|--webfiles-repo)
    WEBFILES_REPO="$2"
    shift # past argument
    ;;
    # There used to be a typo so support both spellings
    -b|--webfile-branch|--webfiles-branch)
    WEBFILES_BRANCH="$2"
    shift # past argument
    ;;
    *)
        # unknown option
    ;;
esac
shift # past argument or value
done

if [ "$HELP" == "1" ];
then
    cat <<EOF
Usage: ./prepare.sh [-h] [--webfiles-repo WEBFILES_REPO]
                         [--webfiles-branch WEBFILES_BRANCH]

Prepares the Cordova app. Requires npm and Python 2.x with virtualenv.

optional arguments:
  -h, --help                       show this help message and exit
  --webfiles-repo WEBFILES_REPO, -r WEBFILES_REPO
                                   Optional non-default git URL to clone web
                                   files from. (Default: $WEBFILES_REPO)
  --webfiles-branch WEBFILES_BRANCH, -b WEBFILES_BRANCH
                                   Optional non-default git URL to clone web
                                   files from. (Default: $WEBFILES_BRANCH)
EOF
    exit 1
fi

if [ \! -e webfiles ]; then
    git clone --depth 1 https://github.com/greenaddress/GreenAddressWebFiles.git -b electron webfiles # FIXME: Undo
    #git clone --depth 1 $WEBFILES_REPO -b $WEBFILES_BRANCH webfiles
fi

# Add the wally plugin:
if [ \! -e libwally-core ]; then
    git clone https://github.com/ElementsProject/libwally-core -b master --depth 1
fi
# Build the wally plugin
./prepare_wally.sh

if [ \! -e venv ]; then
    virtualenv venv
    venv/bin/pip install -r webfiles/requirements.txt
fi

cd webfiles

# 1. Build *.js:
if [ \! -e node_modules ]; then
    npm i
fi
npm run build

# 2. Render *.html:
../venv/bin/python render_templates.py -a ../www/greenaddress.it

# 3. Copy *.js:
cp ../www/greenaddress.it/static/wallet/{config,network}.js /tmp
rm -rf ../www/greenaddress.it/static
cp -r build/static ../www/greenaddress.it/static
rm -rf ../www/greenaddress.it/static/js/jsqrcode  # crx only
rm -rf ../www/greenaddress.it/static/js/btchip-js-api  # crx only

# Cordova actually requires a subset of btchip files:
mkdir -p ../www/greenaddress.it/static/js/btchip-js-api/api
mkdir -p ../www/greenaddress.it/static/js/btchip-js-api/thirdparty
cp build/static/js/btchip-js-api/api/{ByteString,Convert,GlobalConstants}.js ../www/greenaddress.it/static/js/btchip-js-api/api
cp -r build/static/js/btchip-js-api/thirdparty/{async,class,q} ../www/greenaddress.it/static/js/btchip-js-api/thirdparty

rm ../www/greenaddress.it/static/js/{greenaddress,instant}.js  # web only
mkdir -p ../www/greenaddress.it/static/wallet/ >/dev/null
mv /tmp/{config,network}.js ../www/greenaddress.it/static/wallet/

cd ..
cordova plugin add plugins-src/cordova-plugin-greenaddress --save
