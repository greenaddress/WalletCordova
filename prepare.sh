#!/bin/bash

set -e

WEBFILES_REPO="https://github.com/greenaddress/GreenAddressWebFiles.git"
WEBFILES_BRANCH=$(git symbolic-ref HEAD || echo $TRAVIS_BRANCH)
WEBFILES_BRANCH=${WEBFILES_BRANCH##refs/heads/}

WEBFILES_BRANCH=electron  # TODO use the usual branches

while [ $# -gt 0 ]; do
key="$1"

case $key in
    -h|--help)
    HELP=1
    ;;
    -s|--silent)
    SILENT=1
    ;;
    -r|--webfiles-repo)
    WEBFILES_REPO="$2"
    shift # past argument
    ;;
    -b|--webfile-branch)
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
                         [--silent]

Prepares the Cordova app. Requires npm and Python 2.x with virtualenv.

optional arguments:
  -h, --help                       show this help message and exit
  --webfiles-repo WEBFILES_REPO, -r WEBFILES_REPO
                                   Optional non-default git URL to clone web
                                   files from. (Default:
                                     $WEBFILES_REPO)
  --webfiles-branch WEBFILES_BRANCH, -b WEBFILES_BRANCH
                                   Optional non-default git URL to clone web
                                   files from. (Default: $WEBFILES_BRANCH)
  --silent, -s                     Silently ignore already existing webfiles
                                   directory. When not passed, the script will
                                   ask if it should remove it.
EOF
    exit 1
fi

if [ -e webfiles ] && [ "$SILENT" != "1" ]; then
    echo -n "webfiles exists. do you want to remove it? (y/n) "
    read REMOVE
    if [ "$REMOVE" == "y" ]; then
        rm -rf webfiles
    else
        echo "Exiting. Pass the --silent option if you want to ignore existing webfiles."
        exit 1
    fi
fi

if [ \! -e webfiles ]; then
    git clone --depth 1 $WEBFILES_REPO -b $WEBFILES_BRANCH webfiles
fi

# Add the wally plugin:
if [ \! -e libwally-core-cordova ]; then
    git clone https://github.com/jkozera/libwally-core-cordova.git
fi
cd libwally-core-cordova
if [ \! -e libwally-core ]; then
    git clone https://github.com/jkozera/libwally-core.git -b wip_js
fi

if ./prepare_libwally_clang.sh; then
    # Android succeeded
    cp libwally-core/src/swig_java/src/com/blockstream/libwally/Wally.java wallyplugin
else
    # try building for ios only
    (cd ./libwally-core && ./tools/autogen.sh && ./configure && make)
fi
cd wallyplugin
python ../libwally-core/src/swig_js/makewrappers/wrap.py
mkdir -p build/Release
echo '' > build/Release/wallycore.js  # mock wallycore which is nodejs-only
npm i base64-js
cd ../..

if [ "$(uname -s)" == "Darwin" ]; then
    # TODO move to Cordova plugin scripts
    cp -r libwally-core-cordova/libwally-core/src/swig_js/libwally-core-ios/libwally-core-ios.xcodeproj libwally-core-cordova/wallyplugin
    cordova prepare ios
    # plugin add doesn't work before prepare for iOS
    sed -i '' s/HelloCordova/GreenAddress/ libwally-core-cordova/wallyplugin/scripts/add_swift_support.js
    cordova plugin add libwally-core-cordova/wallyplugin
    sed -i '' s/HelloCordova/GreenAddress/ libwally-core-cordova/patch_pbxproj_with_wally.js
    NODE_PATH=`pwd`/platforms/ios/cordova/node_modules node libwally-core-cordova/patch_pbxproj_with_wally.js > pbxproj.new
    cp -r libwally-core-cordova/libwally-core/src/* platforms/ios/GreenAddress
    cp -r libwally-core-cordova/libwally-core/include platforms/ios/GreenAddress
    cp -r libwally-core-cordova/libwally-core/src/secp256k1/include/* platforms/ios/GreenAddress/include/
    mv pbxproj.new platforms/ios/GreenAddress.xcodeproj/project.pbxproj
else
    cordova plugin add libwally-core-cordova/wallyplugin
fi

if [ \! -e venv ]; then
    virtualenv venv
fi
venv/bin/pip install -r webfiles/requirements.txt

cd webfiles

# 1. Build *.js:
npm i
npm run build
rm -rf node_modules

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
