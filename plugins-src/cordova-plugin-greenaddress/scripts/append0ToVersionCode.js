var path = require('path'),
    fs = require('fs');

module.exports = function(context) {
    var et = context.requireCordovaModule('elementtree'),
        manifestPath = path.join(context.opts.projectRoot, 'platforms', 'android', 'AndroidManifest.xml'),
        manifestContents = fs.readFileSync(manifestPath, { encoding: 'utf8' }),
        manifest = et.parse(manifestContents),
        versionCode = manifest.getroot().get('android:versionCode') + '',
        buildExtrasPath = path.join(context.opts.projectRoot, 'platforms', 'android', 'build-extras.gradle');

    if (context.opts.cordova.plugins.indexOf('cordova-plugin-crosswalk-webview') === -1) {
        versionCode += '0'
    }
    var data = fs.readFileSync(buildExtrasPath)
    //fs.writeFileSync(buildExtrasPath, data+"\next.cdvVersionCode=" + versionCode, { encoding: 'utf8' });
};
