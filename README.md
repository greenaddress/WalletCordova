Build status: [![Build Status](https://travis-ci.org/greenaddress/WalletCordova.png?branch=master)](https://travis-ci.org/greenaddress/WalletCordova)

## How to build

 1. Run `./prepare.sh` (Note that for Android it requires the environment variables `ANDROID_NDK` and `JAVA_HOME` to be set.)
 2. Follow platform-specific instructions below

## How to build on Android

 1. Install Android SDK and Cordova (7.0.1)
 2. `cd` to the WalletCordova directory
 3. Run `cordova prepare android`
 4. Run `cordova build android`

After following these steps you should get a debug apk file in `platforms/android/build/outputs/apk/android-debug.apk`.

## How to build on iOS (available on macOS only)

There's an issue with `xcode` node library causing `cordova prepare ios` to fail silently. See https://github.com/apla/me.apla.cordova.app-preferences/issues/65 for a workaround.

 1. Install Xcode and Cordova
 2. `cd` to the WalletCordova directory
 3. Run `cordova build ios` (`prepare ios` was called already by prepare.sh)

After following these steps you should get an .app in platforms/ios/build/emulator/GreenAddress.It.app.
