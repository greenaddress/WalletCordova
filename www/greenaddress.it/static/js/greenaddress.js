var disableEuCookieComplianceBanner = function() {
    var date = new Date(); date.setTime(date.getTime() + (5*365*24*60*60*1000));
    var expires = "; expires=" + date.toGMTString();
    document.cookie = 'eu-cookie-compliance=true; path=/' + expires;
    $('#eu-cookie-compliance').remove();
};

$(document).ready(function() {
    if (!window.cordova && document.cookie.indexOf('eu-cookie-compliance=true') == -1) {
        $('body').append('<div id="eu-cookie-compliance"><span id="eu-cookie-compliance-hide">×</span>'+
            gettext('Cookies help us deliver our services. By using our services, you agree to our use of cookies.')+
                    ' <a href="/faq/#cookies">'+gettext('More information')+'</a></div>');
        $('#eu-cookie-compliance').click(function() {
            disableEuCookieComplianceBanner();
        });
    }
    if (window.chrome && chrome.app) {
        $('#wallet-create, #wallet-login').click(function(ev) {
            ev.preventDefault();
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
