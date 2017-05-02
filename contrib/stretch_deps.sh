#!/usr/bin/env bash
set -e

export SDK_FILENAME=tools_r25.2.3-linux.zip
export NDK_FILENAME=android-ndk-r14b-linux-x86_64.zip

sed -i 's/deb.debian.org/httpredir.debian.org/g' /etc/apt/sources.list
dpkg --add-architecture i386
apt-get -yqq update && apt-get -yqq upgrade
apt-get -yqq install unzip git curl build-essential openjdk-8-jdk ca-certificates-java python-virtualenv python-dev python-pip make swig autoconf libtool pkg-config libc6:i386 libc6-dev:i386 libncurses5:i386 libstdc++6:i386 lib32z1 gradle
curl -sL https://deb.nodesource.com/setup_8.x | bash -
apt-get -yqq update
apt-get -yqq install nodejs
update-java-alternatives -s java-1.8.0-openjdk-amd64

npm install -g cordova

cd /opt && curl -sSO https://dl.google.com/android/repository/${SDK_FILENAME} && unzip -qq ${SDK_FILENAME} && rm ${SDK_FILENAME}
cd /opt && curl -sSO https://dl.google.com/android/repository/${NDK_FILENAME} && unzip -qq ${NDK_FILENAME} && rm ${NDK_FILENAME}

mkdir -p /opt/licenses
echo 8933bad161af4178b1185d1a37fbf41ea5269c55 > /opt/licenses/android-sdk-license
/opt/tools/bin/sdkmanager "tools" "platform-tools"
/opt/tools/bin/sdkmanager "build-tools;25.0.3"
/opt/tools/bin/sdkmanager "platforms;android-25"
/opt/tools/bin/sdkmanager "extras;android;m2repository" "extras;google;m2repository"

rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6*
