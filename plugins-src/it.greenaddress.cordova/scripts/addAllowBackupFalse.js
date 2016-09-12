#!/usr/bin/env node

module.exports = function(context) {
  var fs = context.requireCordovaModule('fs'),
    path = context.requireCordovaModule('path');

  var platformRoot = path.join(context.opts.projectRoot, 'platforms/android');
  var manifestFile = path.join(platformRoot, 'AndroidManifest.xml');

  fs.readFile(manifestFile, 'utf8', function (err, data) {
    if (err) {
      throw new Error('Unable to find AndroidManifest.xml: ' + err);
    }

    var result = data.replace(/<application/g, '<application android:allowBackup="false"');

    fs.writeFile(manifestFile, result, 'utf8', function (err) {
      if (err) throw new Error('Unable to write into AndroidManifest.xml: ' + err);
    })
  });
};
