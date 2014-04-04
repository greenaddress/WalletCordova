## How to build

 1. Install Android SDK and Cordova 3.4
 2. `cd` to the WalletCordova directory
 3. Run `android update project --path platforms/android --subprojects`
 4. Run `android update project --path facebook-android-sdk-3.7/facebook`
 5. Run `cordova build`

After following these steps you should get a debug apk file in `platforms/android/ant-build/GreenAddressIt-debug.apk`.
