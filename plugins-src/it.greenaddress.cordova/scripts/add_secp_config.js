var fs = require('fs'),
    path = require('path');

module.exports = function(context) {
    var COMMENT_KEY = /_comment$/;
    var xcode = context.requireCordovaModule('xcode');

    var projectRoot = process.argv[2];
    //if run for plugin projectRoot initialy is platform
    projectRoot = path.resolve(path.join(projectRoot,'..'));

    var iosPlatformPath = path.join(projectRoot, 'platforms', 'ios'),
        iosProjectPath = path.join(iosPlatformPath, 'GreenAddress.xcodeproj', 'project.pbxproj'),
        platform_ios = context.requireCordovaModule('cordova-lib/src/plugman/platforms/ios');
        projectFile = platform_ios.parseProjectFile(iosPlatformPath),
        xcodeProject = projectFile.xcode,
        configurations = nonComments(xcodeProject.pbxXCBuildConfigurationSection());

    for (var config in configurations) {
        /*
        console.log('1' + config)
        console.log(configurations[config])
        console.log(configurations[config].buildSettings)
        */

        var buildSettings = configurations[config].buildSettings;
        var defs = buildSettings['GCC_PREPROCESSOR_DEFINITIONS'] || [];
        if (defs.indexOf('USE_FIELD_INV_BUILTIN') != -1) {
            // these objects have multiple references,
            // so avoid adding the same thing twice:
            continue;
        }
        defs.push.apply(
            defs,
            ["USE_NUM_NONE",
             "USE_SCALAR_8X32",
             "USE_FIELD_10X26",
             "USE_SCALAR_INV_BUILTIN",
             "USE_FIELD_INV_BUILTIN"]
        );
        buildSettings['GCC_PREPROCESSOR_DEFINITIONS'] = defs;
    }

    // fs.writeFileSync(iosProjectPath, xcodeProject.writeSync());
    projectFile.write();

    function nonComments(obj) {
        var keys = Object.keys(obj),
            newObj = {},
            i = 0;

        for (i; i < keys.length; i++) {
            if (!COMMENT_KEY.test(keys[i])) {
                newObj[keys[i]] = obj[keys[i]];
            }
        }

        return newObj;
    }
}