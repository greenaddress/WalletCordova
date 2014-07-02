#!/bin/bash

# This script replicates some minimal Cordova's functionality for the purpose
# of building GreenAddress on F-Droid servers. They don't provide nodejs,
# so running Cordova's toolset is not possible there.

ln -s $PWD/CordovaLib/bin CordovaLib/ant-build
ln -s $PWD/../../facebook-android-sdk-3.7/facebook/bin $PWD/../../facebook-android-sdk-3.7/facebook/ant-build
cp -r ../../www/* assets/www
cp -r platform_www/* assets/www
cp -r ../../plugins/me.apla.cordova.app-preferences/www/task assets/www

cd scrypt
export PATH=$ANDROID_NDK/toolchains/arm-linux-androideabi-4.8/prebuilt/linux-x86/bin:$PATH
make NDK_ROOT=$ANDROID_NDK TARGET=android
cd ..
cp scrypt/target/libscrypt.so libs/armeabi
