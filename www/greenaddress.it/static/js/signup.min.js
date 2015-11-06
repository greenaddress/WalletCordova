var SignupControllerAsync = (function() {
var signup = {};  // bleh (see comment below)
var secured_confirmed;
return ['$scope', '$location', 'mnemonics', 'tx_sender', 'notices', 'wallets', '$window', 'facebook', '$modal', 'gaEvent', '$q', 'reddit', 'storage', 'trezor', 'btchip', 'bip38', '$interval', '$sce', 'hw_detector', 'user_agent',
        function SignupController($scope, $location, mnemonics, tx_sender, notices, wallets, $window, facebook, $modal, gaEvent, $q, reddit, storage, trezor, btchip, bip38, $interval, $sce, hw_detector, user_agent) {
    // some Android devices have window.WebSocket defined and yet still don't support WebSockets
    var isUnsupportedAndroid = navigator.userAgent.match(/Android 4.0/i) ||
                               navigator.userAgent.match(/Android 4.1/i) ||
                               navigator.userAgent.match(/Android 4.2/i) ||
                               navigator.userAgent.match(/Android 4.3/i);
    var isIE = navigator.userAgent.match(/MSIE/i) || navigator.userAgent.match(/Trident/i);
    var isChrome = navigator.userAgent.match(/Chrome/i);
    var is_chrome_app = window.chrome && chrome.storage;
    if (!window.cordova && (isIE || !window.crypto || !window.WebSocket || !window.Worker || (isUnsupportedAndroid && !isChrome))) {
        $location.path('/browser_unsupported');
        return;
    }
    var requires_mnemonic = ($location.path() == '/signup_pin' || $location.path() == '/signup_oauth' || $location.path() == '/signup_2factor');
    if (requires_mnemonic && !signup.mnemonic && !tx_sender.trezor_dev) {
        $location.path('/create');
        return;
    }
    var first_page = false;
    if (!$scope.wallet.signup) {  // clear for case of other signup done previously in the same browser/crx session
        first_page = true;
        for (k in signup) {
            signup[k] = undefined;
        }
    }
    $scope.signup = signup;
    signup.empty_mytrezor_message = gettext('Please go to %s first to set up your device.');
    if (is_chrome_app) {
        signup.empty_mytrezor_message = $sce.trustAsHtml(signup.empty_mytrezor_message.replace(
            '%s',
            '<a href="https://mytrezor.com/" target="_blank">myTREZOR</a>'));
    } else {
        // don't use target _blank for browser because the signup page needs refreshing
        // after TREZOR setup anyway
        signup.empty_mytrezor_message = $sce.trustAsHtml(signup.empty_mytrezor_message.replace(
            '%s',
            '<a href="https://mytrezor.com/">myTREZOR</a>'));
    }
    if ($location.path() == '/trezor_signup') {
        signup.is_trezor = true;
        signup.seed_progress = 100;
    } else if ($location.path() == '/create') {
        signup.is_trezor = false;
    }
    signup.noLocalStorage = storage.noLocalStorage;
    $scope.$digest();  // not sure why is this necessary, but i'm already too annoyed with this JS to find out...
    $scope.wallet.hidden = true;
    $scope.wallet.signup = true;

    var trezor_dev;

    var signup_with_btchip = function(hd_deferred) {
        btchip.getDevice().then(function(btchip_dev) {
            btchip_dev.app.verifyPin_async(new ByteString($scope.signup.btchip_pin, ASCII)).then(function() {
                $scope.signup.seed_progress = 0;
                var expected_signing_ms = 6000, elapsed_signing_ms = 0
                $scope.signup.seed_progress = 0;
                var countdown = $interval(function() {
                    elapsed_signing_ms += 100;
                    $scope.signup.seed_progress = Math.max(1, Math.round(100*elapsed_signing_ms/expected_signing_ms));
                    if ($scope.signup.seed_progress >= 100) {
                        // second login is faster because pubkey is already derived:
                        expected_signing_ms = 4500;
                        $interval.cancel(countdown);
                    }
                }, 100);
                btchip_dev.app.getWalletPublicKey_async('').then(function(result) {
                    var ecPub = new Bitcoin.ECPubKey(Bitcoin.convert.hexToBytes(result.publicKey.toString(HEX)));
                    hd_deferred.resolve({
                        master_public: ecPub.toHex(true),  // compressed master pubkey
                        master_chaincode: result.chainCode.toString(HEX),
                        btchip_pubkey: result,
                        btchip_dev: btchip_dev
                    });
                }).fail(function(error) {
                    $scope.signup.login_failed = true;
                    btchip_dev.dongle.disconnect_async();
                    notices.makeNotice("error", error);
                });
            }).fail(function(error) {
                btchip_dev.dongle.disconnect_async();
                if (error.indexOf("6982") >= 0) {
                    notices.makeNotice("error", gettext("Invalid PIN"));
                } else if (error.indexOf("6985") >= 0) {
                    notices.makeNotice("error", gettext("Dongle is not set up"));
                } else if (error.indexOf("6faa") >= 0) {
                    notices.makeNotice("error", gettext("Dongle is locked - reconnect the dongle and retry"));
                } else {
                    notices.makeNotice("error", error);
                }
            });
        });
    }

    var signup_with_trezor = function(hd_deferred) {
        trezor.getDevice().then(function(trezor_dev) {
            trezor_dev.getPublicKey([]).then(function(result) {
                var hdwallet = Bitcoin.HDWallet.fromBase58(result.message.xpub);
                hd_deferred.resolve({
                    master_public: hdwallet.pub.toHex(),
                    master_chaincode: Bitcoin.convert.bytesToHex(hdwallet.chaincode),
                    trezor_dev: trezor_dev
                })
            })
        })
    }

    if (signup.fbloginstate === undefined) {
        secured_confirmed = $q.defer();
        signup.fbloginstate = {};
        signup.redditloginstate = {};
        signup.customloginstate = {};
        if (!signup.is_trezor)
            signup.seed_progress = 0;
        var entropy, hdwallet;

        var generate_mnemonic = function() {
            $scope.signup.unexpected_error = false;
            var max256int_hex = '';
            while (max256int_hex.length < 256/4) max256int_hex += 'F';
            var TWOPOWER256 = new Bitcoin.BigInteger(max256int_hex, 16).add(Bitcoin.BigInteger.ONE);
            entropy = Bitcoin.ecdsa.getBigRandom(TWOPOWER256).toByteArrayUnsigned();
            $scope.signup.seed = Bitcoin.convert.bytesToHex(entropy);
            while (entropy.length < 32) entropy.unshift(0);
            mnemonics.toMnemonic(entropy).then(function(mnemonic) {
                mnemonics.toSeed(mnemonic).then(function(seed) {
                    mnemonics.toSeed(mnemonic, 'greenaddress_path').then(function(path_seed) {
                        $q.when(Bitcoin.HDWallet.fromSeedHex(seed, cur_net)).then(function(hdwallet) {
                            secured_confirmed.promise.then(function() {
                                hdwallet.seed_hex = seed;
                                if ($scope.wallet.mnemonic) {
                                    // no hardware wallet because user confirmed they backed up their seed:
                                    $scope.wallet.nohw_chosen = true;
                                    var hd_promise = $q.when({
                                        master_public: hdwallet.pub.toHex(),
                                        master_chaincode: Bitcoin.convert.bytesToHex(hdwallet.chaincode)
                                    });
                                } else {
                                    // hw wallet
                                    var hd_deferred = $q.defer(), hd_promise = hd_deferred.promise;
                                    if ($scope.signup.has_btchip) {
                                        signup_with_btchip(hd_deferred);
                                    } else {
                                        signup_with_trezor(hd_deferred);
                                    }
                                }
                                hd_promise.then(function(hd) {
                                    tx_sender.call('http://greenaddressit.com/login/register',
                                            hd.master_public, hd.master_chaincode,
                                            user_agent($scope.wallet)).then(function(data) {
                                        if (hd.btchip_pubkey) {
                                            var login_d = wallets.login_btchip($scope, hd.btchip_dev, hd.btchip_pubkey, undefined, true);
                                        } else if (hd.trezor_dev) {
                                            var login_d = hd.trezor_dev.getPublicKey([18241 + 0x80000000]).then(function(pubkey) {
                                                var cc = pubkey.message.node.chain_code, pk = pubkey.message.node.public_key;
                                                cc = cc.toHex ? cc.toHex() : cc;
                                                pk = pk.toHex ? pk.toHex() : pk;
                                                var extended = cc.toUpperCase() + pk.toUpperCase();
                                                var path = Bitcoin.CryptoJS.HmacSHA512(extended, 'GreenAddress.it HD wallet path');
                                                path = Bitcoin.CryptoJS.enc.Hex.stringify(path);
                                                return wallets.login_trezor($scope, hd.trezor_dev, path, true, false);
                                            });
                                        } else {
                                            var login_d = wallets.login($scope, hdwallet, mnemonic, true, false, path_seed, undefined, true);
                                        }
                                        login_d.then(function(data) {
                                            gaEvent('Signup', 'LoggedIn');
                                            if ($scope.wallet.signup_fb_prelogged_in) {
                                                $scope.signup.fblogin();
                                            }
                                            if ($scope.wallet.signup_reddit_prelogged_in) {
                                                $scope.signup.redditlogin($scope.wallet.signup_reddit_prelogged_in);
                                            }
                                            $scope.signup.logged_in = data;
                                            if (!data) $scope.signup.login_failed = true;
                                            if (data && !data.first_login) {
                                                notices.makeNotice('success', gettext('You were already registered, so we logged you in.'));
                                                $location.path('/info');
                                            }
                                        });
                                    });
                                });
                            });
                        });
                    }, null, function(progress) {
                        $scope.signup.seed_progress = Math.round(50 + progress/2);
                    });
                }, function(err) {
                    $scope.signup.unexpected_error = err;
                }, function(progress) {
                    // any progress means the mnemonic is valid so we can display it
                    if (!($scope.has_trezor || $scope.has_btchip)) {
                        $scope.wallet.mnemonic = $scope.signup.mnemonic = mnemonic;
                        $scope.signup.seed_progress = Math.round(progress/2);
                    }
                });
            }, function(err) {
                $scope.signup.unexpected_error = err.status || err;
            });
        };
        if (signup.is_trezor) {
            trezor.getDevice(true).then(function(dev) {
                $scope.trezor_dev = trezor_dev = dev;
                trezor_dev.getPublicKey([]).then(function(pubkey) {
                    $scope.$apply(function() {
                        var trezor_chaincode = pubkey.message.node.chain_code;
                        var trezor_pubkey = pubkey.message.node.public_key;
                        tx_sender.call('http://greenaddressit.com/login/register',
                            trezor_pubkey, trezor_chaincode,
                            user_agent($scope.wallet)).then(try_login, try_login);
                    });
                });
            });

            var try_login = function() {
                var path_seed = [];
                trezor_dev.getPublicKey([18241 + 0x80000000]).then(function(pubkey) {
                    var extended = pubkey.message.node.chain_code + pubkey.message.node.public_key;
                    var path = Bitcoin.CryptoJS.HmacSHA512(extended, 'GreenAddress.it HD wallet path');
                    path = Bitcoin.CryptoJS.enc.Hex.stringify(path);
                    wallets.login_trezor($scope, trezor_dev, path, true, false).then(function(data) {
                        gaEvent('Signup', 'LoggedIn');
                        if ($scope.wallet.signup_fb_prelogged_in) {
                            $scope.signup.fblogin();
                        }
                        if ($scope.wallet.signup_reddit_prelogged_in) {
                            $scope.signup.redditlogin($scope.wallet.signup_reddit_prelogged_in);
                        }
                        $scope.signup.logged_in = data;
                        if (!data) $scope.signup.login_failed = true;
                    });
                });
            };

        } else {
            generate_mnemonic();
        }
    }

    $scope.signup.try_again = function() {
        // should not ever happen, but just in case we have another bug
        generate_mnemonic();
    };

    var secured_confirmed_resolved = false;
    $scope.$watch('signup.secured_confirmed', function(newValue, oldValue) {
        if (newValue == oldValue) return;
        if (newValue && !secured_confirmed_resolved) {
            if (window.disableEuCookieComplianceBanner) {
                disableEuCookieComplianceBanner();
            }
            secured_confirmed.resolve(true);
            secured_confirmed_resolved = true;
        }
    });

    $scope.signup.set_pin = function() {
        var next_page = '/signup_oauth';
        if (!$scope.signup.pin) {
            gaEvent('Signup', 'PinSkippedToOauth');
            $location.url(next_page + '#content_container');
            return;
        }
        $scope.signup.setting_pin = true;
        wallets.create_pin($scope.signup.pin.toString(), $scope).then(function() {
            gaEvent('Signup', 'PinSet');
            $scope.signup.pin_set = true;
            $scope.signup.setting_pin = false;
            $location.url(next_page);
        }, function(failure) {
            gaEvent('Signup', 'PinSettingFailed', failure);
            notices.makeNotice('error', 'Failed setting PIN.' + (failure ? ' ' + failure : ''));
            $scope.signup.setting_pin = false;
        });

    };

    $scope.signup.fblogin = function() {
        gaEvent('Signup', 'FbLoginClicked');
        facebook.login($scope.signup.fbloginstate).then(function() {
            var auth = FB.getAuthResponse();
            $scope.signup.social_in_progress = true;
            tx_sender.call('http://greenaddressit.com/addressbook/sync_fb', auth.accessToken).then(function() {
                gaEvent('Signup', 'FbSyncEnabled');
                $scope.signup.social_in_progress = false;
                $scope.signup.any_social_done = true;
                $scope.signup.fbloginstate.synchronized = true;
            }, function(err) {
                gaEvent('Signup', 'FbSyncFailed', err.desc);
                notices.makeNotice('error', err.desc);
                $scope.signup.social_in_progress = false;
                $scope.signup.fbloginstate.logged_in = false;
            });
        });
    };

    $scope.signup.customlogin = function() {
        gaEvent('Signup', 'CustomLoginClicked');
        $scope.got_username_password = function(username, password) {
            tx_sender.call('http://greenaddressit.com/addressbook/sync_custom', username, password).then(function() {
                gaEvent('Signup', 'CustomLoginEnabled');
                notices.makeNotice('success', gettext('Custom login enabled'));
                $scope.signup.any_social_done = true;
                $scope.signup.customloginstate.synchronized = true;
                modal.close();
            }, function(err) {
                gaEvent('Signup', 'CustomLoginEnableFailed', err.desc);
                notices.makeNotice('error', err.desc);
            });
        };
        var modal = $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_custom_login.html',
            scope: $scope
        });
    }

    $scope.signup.redditlogin = function(token) {
        gaEvent('Signup', 'RedditLoginClicked');
        if (token) {
            var d = $q.when(token);
        } else {
            var d = reddit.getToken('identity');
        }
        d.then(function(token) {
            if (token) {
                $scope.signup.social_in_progress = true;
                tx_sender.call('http://greenaddressit.com/addressbook/sync_reddit', token).then(function() {
                    gaEvent('Signup', 'RedditSyncEnabled');
                    $scope.signup.social_in_progress = false;
                    $scope.signup.any_social_done = true;
                    $scope.signup.redditloginstate.synchronized = true;
                }, function(err) {
                    gaEvent('Signup', 'RedditSyncEnableFailed');
                    notices.makeNotice('error', err.desc);
                    $scope.signup.social_in_progress = false;
                    that.toggling_reddit = false;
                });
            }
        });
    };

    $scope.signup.qrmodal = function() {
        gaEvent('Signup', 'QrModal');
        $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signup_qr_modal.html',
            scope: $scope
        });
    };

    $scope.signup.nfcmodal = function() {
        gaEvent('Signup', 'NfcModal');
        var mnemonic, mime;
        if ($scope.signup.mnemonic_encrypted) {
            mnemonic = $scope.signup.mnemonic_encrypted;
            mime = 'x-ga/en';
        } else {
            mnemonic = $scope.wallet.mnemonic;
            mime = 'x-gait/mnc';
        }
        mnemonics.validateMnemonic(mnemonic).then(function(bytes) {
            $scope.nfc_bytes = bytes;
            $scope.nfc_mime = mime;
            $modal.open({
                templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signup_nfc_modal.html',
                scope: $scope,
                controller: 'NFCController'
            });
        });
    };

    $scope.signup.encrypt_mnemonic = function() {
        gaEvent('Signup', 'EncryptMnemonic');
        bip38.encrypt_mnemonic_modal($scope, Bitcoin.convert.hexToBytes($scope.signup.seed)).then(function(encrypted) {
            $scope.signup.mnemonic_encrypted = encrypted;
        });
    };

    $scope.signup.usbmodal = function() {
        var that = this;
        that.hw_wallet_processing = true;
        btchip.getDevice().then(function () {
            btchip.setupSeed($scope.wallet.mnemonic).then(function () {
                $scope.signup.has_btchip = true;
            });
        }).finally(function () {
            that.hw_wallet_processing = false;
        })
    }

    $scope.signup.usb_hwseed_modal = function() {
        if (!is_chrome_app) { hw_detector.showModal(); return; }
        var that = this;
        that.hw_wallet_processing = true;
        btchip.getDevice().then(function () {
            return btchip.setupSeed().then(function(result) {
                delete $scope.wallet.mnemonic;
                $scope.signup.mnemonic = gettext('Mnemonic not available when using hardware wallet seed');

                $scope.signup.has_btchip = true;
                $scope.signup.btchip_pin = result.pin;
            });
        }).finally(function() { that.hw_wallet_processing = false; })
    }

    if (first_page) {
        trezor.getDevice('retry').then(function (trezor_dev) {
            if (secured_confirmed_resolved) return;
            if (hw_detector.modal) {
                hw_detector.success = true;
                hw_detector.modal.close();
            }
            delete $scope.wallet.mnemonic;
            trezor_dev.getPublicKey([]).then(function () {
                $scope.signup.trezor_detected = true;
                $scope.signup.has_trezor = true;
            }).catch(function (e) {
                if (e.code = "Failure_NotInitialized") {
                    $scope.signup.trezor_detected = true;
                    $scope.signup.empty_trezor = true;
                }
            });
        });
    }

}]})();
