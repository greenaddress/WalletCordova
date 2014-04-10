angular.module('greenWalletSignupLoginControllers', ['greenWalletMnemonicsServices'])
.controller('SignupLoginController', ['$scope', '$modal', 'focus', 'wallets', 'notices', 'mnemonics', '$location', 'cordovaReady', 'facebook', 'tx_sender', 'crypto', 'gaEvent', 'reddit', 'storage', 'qrcode',
        function SignupLoginController($scope, $modal, focus, wallets, notices, mnemonics, $location, cordovaReady, facebook, tx_sender, crypto, gaEvent, reddit, storage, qrcode) {
    var state = {};
    storage.get(['pin_ident', 'encrypted_seed', 'pin_refused']).then(function(data) {
        state.has_pin = data.pin_ident && data.encrypted_seed;
        state.refused_pin = data.pin_refused || storage.noLocalStorage;  // don't show the PIN popup if no storage is available
        state.pin_ident = data.pin_ident;
        state.encrypted_seed = data.encrypted_seed;
    });
    if ($scope.wallet) {
        $scope.wallet.signup = false;  // clear signup state
    }
    $scope.state = state;
    var modal;

    $scope.login = function() {
        $scope.logging_in = true;
        if (use_pin_data.pin) {
            gaEvent('Login', 'PinLogin');
            $scope.use_pin().finally(function() {
                $scope.logging_in = false;
            });
            return;
        }
        gaEvent('Login', 'MnemonicLogin');
        state.mnemonic_error = state.login_error = undefined;
        return mnemonics.validateMnemonic(state.mnemonic).then(function() {
            return mnemonics.toSeed(state.mnemonic).then(function(seed) {
                return mnemonics.toSeed(state.mnemonic, 'greenaddress_path').then(function(path_seed) {
                    var hdwallet = new GAHDWallet({seed_hex: seed});
                    // seed, mneomnic, and path seed required already here for PIN setup below
                    $scope.wallet.hdwallet = hdwallet;
                    $scope.wallet.mnemonic = state.mnemonic;
                    $scope.wallet.gait_path_seed = path_seed;
                    state.seed_progress = 100;
                    state.seed = seed;
                    var do_login = function() {
                        return wallets.login($scope, hdwallet, state.mnemonic, false, false, path_seed).then(function(data) {
                            if (!data) {
                                gaEvent('Login', 'MnemonicLoginFailed');
                                state.login_error = true;
                            } else {
                                gaEvent('Login', 'MnemonicLoginSucceeded');
                            }
                        });
                    };
                    if (!state.has_pin && !state.refused_pin) {
                        gaEvent('Login', 'MnemonicLoginPinModalShown');
                        modal = $modal.open({
                            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_pin.html',
                            scope: $scope
                        });
                        modal.opened.then(function() { focus("pinModal"); });
                        return modal.result.then(do_login, function() {
                            storage.set('pin_refused', true);
                            return do_login();
                        })
                    } else {
                        return do_login();
                    }
                }, undefined, function(progress) {
                    state.seed_progress = Math.round(50 + progress/2);
                });
            }, undefined, function(progress) {
                state.seed_progress = Math.round(progress/2);
            }).catch(function() {
                state.seed_progress = undefined;
            });
        }, function(e) {
            gaEvent('Login', 'MnemonicError', e);
            state.mnemonic_error = e;
        }).finally(function() {
            $scope.logging_in = false;
        });
    };
    
    if ($location.hash()) {
        try {
            var nfc_bytes = Crypto.util.base64ToBytes($location.hash());
        } catch(e) {}
        if (nfc_bytes) {
            gaEvent('Login', 'NfcLogin');
            mnemonics.toMnemonic(nfc_bytes).then(function(mnemonic) {
                state.mnemonic = mnemonic;
                $scope.login();
            });
        } else if (state.has_pin) {
            focus('pin');
        }
    } else if (state.has_pin) {
        focus('pin');
    }

    $scope.set_pin = function set_pin(valid) {
        if (!valid) {
            $scope.state.error = true;
        } else {
            wallets.create_pin(state.new_pin_value, $scope).then(function() {
                gaEvent('Login', 'PinSet');
                modal.close();
            }, function(error) {
                gaEvent('Login', 'PinSettingError', error.desc);
                notices.makeNotice('error', error.desc);
            });
        }
    };

    state.fbloginstate = {};
    $scope.login_with_facebook = function() {
        gaEvent('Login', 'FacebookLogin');
        facebook.login(state.fbloginstate).then(function(succeeded) {
            wallets.loginWatchOnly($scope, 'facebook', FB.getAuthResponse().accessToken).then(function() {
                gaEvent('Login', 'FacebookLoginSucceeded');
            }).catch(function(e) {
                if (e && e.uri == "http://greenaddressit.com/error#usernotfound") {
                    gaEvent('Login', 'FacebookLoginRedirectedToOnboarding');
                    $scope.wallet.signup_fb_prelogged_in = true;
                    $location.path('/create');
                } else {
                    gaEvent('Login', 'FacebookLoginFailed', e && e.desc || e);
                    notices.makeNotice('error', e ? (e.desc || e) : gettext('Unknown error'));
                }
            });
        });
    };

    $scope.login_with_reddit = function() {
        gaEvent('Login', 'RedditLogin');
        reddit.getToken('identity').then(function(token) {
            if (!token) return;
            wallets.loginWatchOnly($scope, 'reddit', token).then(function() {
                gaEvent('Login', 'RedditLoginSucceeded');
            }).catch(function(e) {
                if (e.uri == "http://greenaddressit.com/error#usernotfound") {
                    gaEvent('Login', 'RedditLoginRedirectedToOnboarding');
                    $scope.wallet.signup_reddit_prelogged_in = token;
                    $location.path('/create');
                } else {
                    gaEvent('Login', 'RedditLoginFailed', e.desc);
                    notices.makeNotice('error', e.desc);
                }
            });
        });
    };

    $scope.login_with_custom = function() {
        gaEvent('Login', 'CustomLogin');
        $scope.got_username_password = function(username, password) {
            wallets.loginWatchOnly($scope, 'custom', {username: username, password: password}).then(function() {
                gaEvent('Login', 'CustomLoginSucceeded');
                modal.close();
            }).catch(function(e) {
                gaEvent('Login', 'CustomLoginFailed', e.desc);
                notices.makeNotice('error', e.desc);
            });
        };
        var modal = $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_custom_login.html',
            scope: $scope
        });
        
    };
    
    $scope.read_qr_code = function read_qr_code($event) {
        gaEvent('Login', 'QrScanClicked');
        qrcode.scan($scope, $event, '_login').then(function(text) {
            gaEvent('Login', 'QrScanningSucceeded');
            state.mnemonic = text;
            return $scope.login();
        }, function(error) {
            gaEvent('Login', 'QrScanningFailed', error);
            notices.makeNotice('error', error);
        });
    };
    $scope.stop_scanning_qr_code = function() {
        qrcode.stop_scanning($scope);
    }

    var use_pin_data = $scope.use_pin_data = {};

    $scope.use_pin = function(valid) {
        notices.setLoadingText("Checking PIN");
        return tx_sender.call('http://greenaddressit.com/pin/get_password', use_pin_data.pin, state.pin_ident).then(
            function(password) {
                if (!password) {
                    gaEvent('Login', 'PinLoginFailed', 'empty password');
                    state.login_error = true;
                    return;
                }
                tx_sender.pin_ident = state.pin_ident;
                tx_sender.pin = use_pin_data.pin;
                var decoded = crypto.decrypt(state.encrypted_seed, password);
                if(decoded && JSON.parse(decoded).seed) {
                    gaEvent('Login', 'PinLoginSucceeded');
                    var parsed = JSON.parse(decoded);
                    if (!parsed.path_seed) {
                        return mnemonics.toSeed(parsed.mnemonic, 'greenaddress_path').then(function(path_seed) {
                            parsed.path_seed = path_seed;
                            storage.set('encrypted_seed', crypto.encrypt(JSON.stringify(parsed), password));
                            var path = mnemonics.seedToPath(path_seed);
                            var hdwallet = new GAHDWallet({seed_hex: parsed.seed});
                            return wallets.login($scope, hdwallet, state.mnemonic, false, false, path_seed);
                        }, undefined, function(progress) {
                            state.seed_progress = progress;
                        });
                    } else {
                        var hdwallet = new GAHDWallet({seed_hex: parsed.seed});
                        return wallets.login($scope, hdwallet, parsed.mnemonic, false, false, parsed.path_seed);
                    }
                } else {
                    gaEvent('Login', 'PinLoginFailed', 'Wallet decryption failed');
                    state.login_error = true;
                    notices.makeNotice('error', gettext('Wallet decryption failed'));
                }
            }, function(e) {
                gaEvent('Login', 'PinLoginFailed', e.desc);
                notices.makeNotice('error', e.desc || e);
                state.login_error = true;
            });
    }
}]);
