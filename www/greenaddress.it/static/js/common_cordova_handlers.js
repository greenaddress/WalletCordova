var commonNFCXGaitMNCListener = function(nfcEvent) {

    var message = nfcEvent.tag.ndefMessage;
    for (var i = 0; i < message.length; i++) {
        var type = nfc.bytesToString(message[i].type);
        if (type == 'x-gait/mnc' || type == 'x-ga/en') {
            var data = [];
            // convert signed to unsigned:
            for (var j = 0; j < message[i].payload.length; j++) {
                var number = message[i].payload[j];
                data.push(number < 0 ? number + 256 : number);
            }
            window.GA_NFC_LOGIN_DATA = data;
            window.location.href = BASE_URL + '/' + LANG + '/wallet.html#/';
            break;
        }
    }
};

var commonResumeListener = function() {
    console.log('app resumed');
};

var handleOpenURL = function(url) {  // iOS Cordova
    if (url.indexOf('bitcoin:') == 0) {
        location.hash = '#/uri?uri=' + encodeURIComponent(url);
    }
}

var keyboardHide = function() {
    // workaround for http://stackoverflow.com/questions/19169115/phonegap-keyboard-changes-window-height-in-ios-7
    // ('When the keyboard is closed the whole bottom half of the app is gone,')
    var oldScroll = document.body.scrollTop;
    document.body.scrollTop = 0;
    setTimeout(function() { document.body.scrollTop = oldScroll; }, 0);

    // workaround for http://stackoverflow.com/questions/15199072/ios-input-focused-inside-fixed-parent-stops-position-update-of-fixed-elements
    // (Cordova app only)
    document.getElementById('notices_container').setAttribute('style', '');
    document.getElementsByClassName('menu-mobile')[0].setAttribute('style', '');
    document.getElementsByClassName('menu-mobile-bottom')[0].setAttribute('style', '');
    window.removeEventListener('scroll', setNotificationsTop);
}

var keyboardWillShow = function() {
    document.getElementsByClassName('menu-mobile')[0].setAttribute('style',
        'position: absolute');
    document.getElementsByClassName('menu-mobile-bottom')[0].setAttribute('style',
        'position: absolute; bottom: initial; top: ' + (document.height - 35) + "px");
}


var setNotificationsTop = function() {
    document.getElementById('notices_container').setAttribute('style',
            'position: absolute; top: ' + (window.scrollY + 25) + "px");
}

var keyboardDidShow = function() {
    window.addEventListener('scroll', setNotificationsTop);
    setNotificationsTop();
}

document.addEventListener('deviceready', function () {
    console.log('app device ready');
    if (window.nfc) {
        nfc.addMimeTypeListener('x-ga/en', commonNFCXGaitMNCListener);
        nfc.addMimeTypeListener('x-gait/mnc', commonNFCXGaitMNCListener);
        document.addEventListener("offline", function() {
            // workaround for not being able to open local offline.html file
            console.log('redirect to error page via hack');
            window.location.href = window.location.href;
        });
    }
});

