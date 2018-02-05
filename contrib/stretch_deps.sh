#!/usr/bin/env bash
set -e

export SDK_FILENAME=sdk-tools-linux-3859397.zip
export NDK_FILENAME=android-ndk-r14b-linux-x86_64.zip

sed -i 's/deb.debian.org/httpredir.debian.org/g' /etc/apt/sources.list
dpkg --add-architecture i386
apt-get -yqq update && apt-get -yqq upgrade
apt-get -yqq install unzip git curl build-essential openjdk-8-jdk ca-certificates-java python-virtualenv python-dev python-pip make swig autoconf libtool pkg-config libc6:i386 libc6-dev:i386 libncurses5:i386 libstdc++6:i386 lib32z1 gradle
curl -sL https://deb.nodesource.com/setup_8.x | bash -
curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
apt-get -yqq update
apt-get -yqq install nodejs yarn
update-java-alternatives -s java-1.8.0-openjdk-amd64

cd /opt && curl -sSO https://dl.google.com/android/repository/${SDK_FILENAME} && unzip -qq ${SDK_FILENAME} && rm ${SDK_FILENAME}
cd /opt && curl -sSO https://dl.google.com/android/repository/${NDK_FILENAME} && unzip -qq ${NDK_FILENAME} && rm ${NDK_FILENAME}


yes | /opt/tools/bin/sdkmanager "tools" "platform-tools"
yes | /opt/tools/bin/sdkmanager "build-tools;26.0.2"
yes | /opt/tools/bin/sdkmanager "platforms;android-26"
yes | /opt/tools/bin/sdkmanager "extras;android;m2repository" "extras;google;m2repository"
rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6*
