#!/bin/bash

set -e


WEBFILES_REPO="https://github.com/greenaddress/GreenAddressWebFiles.git"
WEBFILES_BRANCH=$(git symbolic-ref HEAD || echo $TRAVIS_BRANCH)
WEBFILES_BRANCH=${WEBFILES_BRANCH##refs/heads/}

MAINNET_CHAINCODE=e9a563d68686999af372a33157209c6860fe79197a4dafd9ec1dbaa49523351d
MAINNET_PUBKEY=0322c5f5c9c4b9d1c3e22ca995e200d724c2d7d8b6953f7b38fddf9296053c961f
TESTNET_CHAINCODE=b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04
TESTNET_PUBKEY=036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3

ID="it.greenaddress.cordova"

SED=sed
if [ "$(uname)" == "Darwin" ]; then
    SED=gsed
    OSX=true
fi

function build_env {
    $SED -e "s/TEMPLATE_COIN/$1/g" network_template.js > www/greenaddress.it/static/wallet/network.js
    $SED -e "s/TEMPLATE_CHAINCODE/$2/g" -e "s/TEMPLATE_PUBKEY/$3/g" -e "s|TEMPLATE_WS|$4|g" \
         -e "s|TEMPLATE_ROOT|$5|g" config_template.js > www/greenaddress.it/static/wallet/config.js
}

function rename_env {
    declare -a filenames=(".cordova/config.json"
                          "plugins-src/cordova-plugin-greenaddress/BTChip.java"
                          "plugins-src/cordova-plugin-greenaddress/GreenAddressIt.java"
                          "plugins-src/cordova-plugin-greenaddress/PINInput.java"
                          "plugins-src/cordova-plugin-greenaddress/PINInputActivity.java"
                          "plugins-src/cordova-plugin-greenaddress/SettingsActivity.java"
                          "plugins-src/cordova-plugin-greenaddress/WalletBalanceWidgetProvider.java"
                          "plugins-src/cordova-plugin-greenaddress/WalletClient.java"
                          "plugins-src/cordova-plugin-greenaddress/plugin.xml")
    for name in "${filenames[@]}"
    do
        $SED -i -e "s/it.greenaddress.cordova/${ID}$1/g" "$name"
    done

    $SED -i -e "s/<widget id=\"it.greenaddress.cordova\"/<widget id=\"${ID}$1\"/" \
            -e "s/<name>GreenAddress/<name>GreenAddress$2/" \
        www/config.xml
}

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
    --mainnet)
    build_env bitcoin ${MAINNET_CHAINCODE} ${MAINNET_PUBKEY} wss://prodwss.greenaddress.it https://greenaddress.it
    if [ -n "$OSX" ]; then
        ID="com.blockstream.greenaddress.cordova"
        rename_env "" ""
    fi
    ;;
    --testnet)
    build_env testnet ${TESTNET_CHAINCODE} ${TESTNET_PUBKEY} wss://testwss.greenaddress.it https://test.greenaddress.it
    if [ -z "$OSX" ]; then
        rename_env _testnet _TestNet
    else
        rename_env .testnet _TestNet
    fi
    ;;
    --regtest)
    build_env testnet ${TESTNET_CHAINCODE} ${TESTNET_PUBKEY} ws://"$2":8080 http://"$2":9908
    rename_env _regtest _RegTest
    shift
    ;;
    --clean)
    git checkout plugins-src www .cordova
    rm -rf package.json package-lock.json plugins platforms node_modules webfiles libwally-core build.json
    exit 0
    ;;
    --team)
    $SED -e "s/DEVELOPMENT_TEAM/$2/" -e "s/PROVISIONING_PROFILE/$3/" build.json.template > build.json
    shift
    shift
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

Prepares the Cordova app. Requires yarn and Python 2.x with virtualenv.

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
    git clone --depth 1 https://github.com/greenaddress/GreenAddressWebFiles.git -b jswally-v0.0.6 webfiles
    $SED -i -e "/wallyjs/d" -e "/cordova-plugin-wally/d" webfiles/package.json
    rm -rf webfiles/package-lock.json
    #git clone --depth 1 $WEBFILES_REPO -b $WEBFILES_BRANCH webfiles
fi

# Add the wally plugin:
if [ \! -e libwally-core ]; then
    git clone https://github.com/ElementsProject/libwally-core -b master
    cd libwally-core
    git checkout 3668617a9dade1a2dc24ab55217ba2a648c8ebb1
    patch -p1 < ../wally.patch
    cd ..
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
    yarn install
fi
yarn run build

# 2. Render *.html:
../venv/bin/python render_templates.py -a ../www/greenaddress.it

# 3. Copy *.js:
tmp_dir=`mktemp -d 2>/dev/null || mktemp -d -t cordova_build`
cp ../www/greenaddress.it/static/wallet/{config,network}.js $tmp_dir
rm -rf ../www/greenaddress.it/static
cp -r build/static ../www/greenaddress.it/static
mkdir -p ../www/greenaddress.it/static/js/lib
cp static/js/lib/common_cordova_handlers.js ../www/greenaddress.it/static/js/lib
rm -rf ../www/greenaddress.it/static/js/jsqrcode  # crx only
rm -rf ../www/greenaddress.it/static/js/btchip-js-api  # crx only

# Cordova actually requires a subset of btchip files:
mkdir -p ../www/greenaddress.it/static/js/btchip-js-api/api
mkdir -p ../www/greenaddress.it/static/js/btchip-js-api/thirdparty
cp build/static/js/btchip-js-api/api/{ByteString,Convert,GlobalConstants}.js ../www/greenaddress.it/static/js/btchip-js-api/api
cp -r build/static/js/btchip-js-api/thirdparty/{async,class,q} ../www/greenaddress.it/static/js/btchip-js-api/thirdparty

rm ../www/greenaddress.it/static/js/{greenaddress,instant}.js  # web only
mkdir -p ../www/greenaddress.it/static/wallet/ >/dev/null
mv $tmp_dir/{config,network}.js ../www/greenaddress.it/static/wallet/
rmdir $tmp_dir

cd ..
cordova plugin add cordova-plugin-urlhandler --variable URL_SCHEME=bitcoin --nosave
cordova plugin add plugins-src/cordova-plugin-greenaddress --nosave --nofetch --noregistry
