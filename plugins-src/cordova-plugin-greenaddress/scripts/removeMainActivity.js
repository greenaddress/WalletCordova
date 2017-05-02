var fs = require('fs');
var path = require('path');

module.exports = function(context) {
    var activity_path = path.join(
        context.opts.projectRoot,
        'platforms', 'android', 'src', 'it', 'greenaddress', 'cordova',
        'MainActivity.java'  // is overridden by GreenAddressIt.java
    );
    if (fs.existsSync(activity_path)) {
        // can be already removed in after_plugin_install
        fs.unlink(activity_path);
    }

    var manifest_path = path.join(
        'platforms', 'android', 'AndroidManifest.xml'
    );
    if (fs.existsSync(manifest_path)) {
        // Android platform can be absent
        var contents = fs.readFileSync(manifest_path, {encoding: 'utf-8'});
        fs.writeFileSync(manifest_path, contents.replace(
            'MainActivity', 'GreenAddressIt'
        ));
    }
}