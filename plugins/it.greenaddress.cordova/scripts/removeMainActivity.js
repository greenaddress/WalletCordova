var fs = require('fs');
var path = require('path');

module.exports = function(context) {
    fs.unlink(path.join(
    	context.opts.projectRoot,
    	'platforms', 'android', 'src', 'it', 'greenaddress', 'cordova',
    	'MainActivity.java'  // is overridden by GreenAddress.java
    ));
}