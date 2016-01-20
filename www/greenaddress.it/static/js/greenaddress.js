var disableEuCookieComplianceBanner = function() {
    var date = new Date(); date.setTime(date.getTime() + (5*365*24*60*60*1000));
    var expires = "; expires=" + date.toGMTString();
    document.cookie = 'eu-cookie-compliance=true; path=/' + expires;
    $('#eu-cookie-compliance').remove();
};

$(document).ready(function() {
    var appInstalled = false;
    if (window.chrome && chrome.runtime) {
        chrome.runtime.sendMessage(
            $('link[rel="chrome-webstore-item"]').attr('href').split('/detail/')[1],
            {greeting: true}, function(response) {
                appInstalled = (response == "GreenAddress installed");
            }
        );
    }

    if (!window.cordova && document.cookie.indexOf('eu-cookie-compliance=true') == -1) {
        $('body').append('<div id="eu-cookie-compliance"><span id="eu-cookie-compliance-hide">×</span>'+
            gettext('Cookies help us deliver our services. By using our services, you agree to our use of cookies.')+
                    ' <a href="/faq/#cookies">'+gettext('More information')+'</a></div>');
        $('#eu-cookie-compliance').click(function() {
            disableEuCookieComplianceBanner();
        });
    }
    if (!(cur_net.isAlpha || cur_net.isSegwit) && window.chrome && chrome.app) {
        $('#wallet-create, #wallet-login').click(function(ev) {
            ev.preventDefault();
            if (appInstalled) {
                if ($(ev.target).attr('id') == 'wallet-create') {
                    window.location.href = "/launch_chrome_app_signup/";
                } else {
                    window.location.href = "/launch_chrome_app/";
                }
                return;
            }
            try {
                chrome.webstore.install();
            } catch (e) {
                location.href = $('link[rel="chrome-webstore-item"]').attr('href')
            }
        });
    }
});
if (window.cordova) { // outside document.ready for better performance
    $(document).ready(function() {
        $('a.navbar-brand').click(function() {
            localStorage.hasWallet = 'showMain'; // disable redirect for this click
        });
    });
    if (localStorage.hasWallet && path_with_no_lang == '') {
        if (localStorage.hasWallet == 'showMain') {
            // one time redirect disabled above
            localStorage.hasWallet = true;
        } else {
            location.href = '/wallet/';
        }
    }
  }
