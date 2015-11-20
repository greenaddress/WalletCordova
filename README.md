## How to build on Android

 1. Install Android SDK and Cordova 5.4
 2. `cd` to the WalletCordova directory
 5. Run `cordova prepare android`
 5. Run `cordova compile android`

After following these steps you should get a debug apk file in `platforms/android/build/outputs/apk/android-debug.apk`.


## How to build on iOS

 1. Install Xcode and Cordova 5.4
 2. `cd` to the WalletCordova directory
 3. Run `cordova prepare ios`
 4. Run `cordova compile ios`

After following these steps you should get an .app in platforms/ios/build/emulator/GreenAddress.It.app.

## Pull Requests

Before making a Pull Request for WalletCordova check if what you want to modify is present in https://github.com/greenaddress/GreenAddressWebFiles - if it is then you should do the PR there.

This repo is updated every time GreenAddressWebFiles is.
