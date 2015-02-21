angular.module('greenWalletSignupLoginControllers', ['greenWalletMnemonicsServices'])
.controller('SignupLoginController', ['$scope', '$modal', 'focus', 'wallets', 'notices', 'mnemonics', '$location', 'cordovaReady', 'facebook', 'tx_sender', 'crypto', 'gaEvent', 'reddit', 'storage', 'qrcode', '$timeout', '$q', 'trezor', 'bip38', 'btchip', '$interval', '$rootScope',
        function SignupLoginController($scope, $modal, focus, wallets, notices, mnemonics, $location, cordovaReady, facebook, tx_sender, crypto, gaEvent, reddit, storage, qrcode, $timeout, $q, trezor, bip38, btchip, $interval, $rootScope) {

    if (window.GlobalWalletControllerInitVars) {
        // in case user goes back from send to login and back to send, we want to display the
        // send data again
        window.WalletControllerInitVars = window.GlobalWalletControllerInitVars;
    }

    var state = {};
    storage.get(['pin_ident', 'encrypted_seed', 'pin_refused']).then(function(data) {
        state.has_pin = data.pin_ident && data.encrypted_seed;
        state.refused_pin = data.pin_refused || storage.noLocalStorage;  // don't show the PIN popup if no storage is available
        state.pin_ident = data.pin_ident;
        state.toggleshowpin = !state.has_pin;
        state.encrypted_seed = data.encrypted_seed;
        $timeout(function() {
            if (!window.cordova || window.cordova.platformId != 'ios') {
                // focus on iOS seems to break the app - clicking anywhere opens
                // the software keyboard which is not what we want
                if (state.has_pin) {
                    focus('pin');
                } else {
                    focus('mnemonic');
                }
            }
        });

        if (state.has_pin && window.cordova && cordova.platformId == 'android') {
            cordovaReady(function() {
                cordova.exec(function(data) {
                    $scope.$apply(function() {
                        use_pin_data.pin = data;
                        $scope.logging_in = true;
                        $scope.use_pin().finally(function() {
                            $scope.logging_in = false;
                        });
                    });
                }, function(fail) {
                    state.toggleshowpin = true;
                }, "PINInput", "show_input", []);
            })();
        }
    });
    if ($scope.wallet) {
        $scope.wallet.signup = false;  // clear signup state
    }
    $scope.state = state;
    if (!('toggleshowpin' in state)) {
        state.toggleshowpin = true;
    }
    state.toggleshowpassword = false;
    var modal;
    var decrypt_bytes = function(bytes) {
        var d = $q.defer();
        $scope.decrypt_password_modal = {
            decrypt: function() {
                this.error = undefined;
                if (!this.password) {
                    this.error = gettext('Please provide a password.');
                    return;
                }
                this.decrypting = true;
                var that = this;
                bip38.processMessage({password: this.password, mnemonic_encrypted: bytes}).then(function(message) {
                    if (message.data.error) {
                        that.decrypting = false;
                        that.error = message.data.error;
                    } else {
                        mnemonics.toMnemonic(message.data).then(function(mnemonic) {
                            that.decrypting = false;
                            d.resolve(mnemonic);
                            modal.close();
                        });
                    }
                }, function(err) { that.error = err; that.decrypting = false; });
            }
        };
        var modal = $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signuplogin/modal_decryption_password.html',
            scope: $scope
        });
        modal.opened.then(function() { focus('decryptPasswordModal'); })
        return d.promise;
    };

    $scope.login = function() {
        if (!state.mnemonic && !use_pin_data.pin) {
            return;
        }

        $scope.logging_in = true;

        if (use_pin_data.pin) {
            gaEvent('Login', 'PinLogin');
            $scope.use_pin().finally(function() {
                $scope.logging_in = false;
            });
            return;
        }
        var encrypted = state.mnemonic.split(" ").length == 27;
        gaEvent('Login', encrypted ? 'MnemonicLogin' : 'MnemonicEncryptedLogin');
        state.mnemonic_error = state.login_error = undefined;
        var mnemonic_words = state.mnemonic.split(' ');
        var last_word = mnemonic_words[mnemonic_words.length-1];
        // BTChip seed ends with 'X':
        if (last_word.indexOf('X') == last_word.length-1) {
            var login_data_d = $q.when({seed: last_word.slice(0, -1)});
        } else {
            var login_data_d = mnemonics.validateMnemonic(state.mnemonic).then(function() {
                var process = function(mnemonic) {
                    return mnemonics.toSeed(mnemonic).then(function(seed) {
                        return mnemonics.toSeed(mnemonic, 'greenaddress_path').then(function(path_seed) {
                            return {seed: seed, path_seed: path_seed, mnemonic: mnemonic};
                        }, undefined, function(progress) {
                            state.seed_progress = Math.round(50 + progress/2);
                        });
                    }, undefined, function(progress) {
                        state.seed_progress = Math.round(progress/2);
                    }).catch(function() {
                        state.seed_progress = undefined;
                    });
                };
                if (!encrypted) {
                    return process(state.mnemonic);
                } else {
                    return mnemonics.fromMnemonic(state.mnemonic).then(function(mnemonic_data) {
                        return decrypt_bytes(mnemonic_data);
                    }).then(process);
                }
            });
        }
        return login_data_d.then(function(data) {
            return $q.when(Bitcoin.HDWallet.fromSeedHex(data.seed, cur_net)).then(function(hdwallet) {
                hdwallet.seed_hex = data.seed;
                // seed, mnemonic, and path seed required already here for PIN setup below
                $scope.wallet.hdwallet = hdwallet;
                $scope.wallet.mnemonic = data.mnemonic;
                $scope.wallet.gait_path_seed = data.path_seed;
                state.seed_progress = 100;
                state.seed = data.seed;
                var do_login = function() {
                    return wallets.login($scope, hdwallet, data.mnemonic, false, false, data.path_seed).then(function(data) {
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
            });
        }, function(e) {
            gaEvent('Login', 'MnemonicError', e);
            state.mnemonic_error = e;
        }).finally(function() {
            $scope.logging_in = false;
        });
    };

    $scope.window = window;
    $scope.$watch('window.GA_NFC_LOGIN_DATA', function(newValue, oldValue) {
        var nfc_bytes = newValue;
        if (nfc_bytes) {
            window.GA_NFC_LOGIN_DATA = undefined;
            var login_with_mnemonic = function(mnemonic) {
                state.mnemonic = mnemonic;
                state.toggleshowpin = true;
                $scope.login();
            }
            if (nfc_bytes.length == 36) {  // encrypted
                gaEvent('Login', 'NfcEncryptedLogin');
                decrypt_bytes(nfc_bytes).then(login_with_mnemonic);
            } else {
                gaEvent('Login', 'NfcLogin');
                mnemonics.toMnemonic(nfc_bytes).then(function(mnemonic) {
                    login_with_mnemonic(mnemonic);
                });
            }
        }
    });

    if (state.has_pin && state.toggleshowpin) {
        focus('pin');
    }

    $scope.$watch('state.toggleshowpin', function(newValue, oldValue) {
        if (newValue) use_pin_data.pin = '';
    });

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

    var trezor_dev = null;

    var login_with_trezor = function() {
        $scope.logging_in = true;
        state.login_error = undefined;
        return wallets.login_trezor($scope, trezor_dev).then(function(data) {},
            function(err) {
                $rootScope.safeApply(function() {
                    $scope.logging_in = false;
                    if (err.message) return;  // handled by TREZOR handleError in services.js
                    notices.makeNotice('error', 'Account not found. Please create a new account with your TREZOR.');
                    $location.url('/create/');
                });
            });
    }

    $scope.login_with_hw = function() {
        gaEvent('Login', 'HardwareLogin');
        if (trezor_dev) { login_with_trezor(); return; }
        btchip.getDevice().then(function(btchip_dev) {
            btchip.promptPin('', function(err, pin) {
                if (!pin) return;
                btchip_dev.app.verifyPin_async(new ByteString(pin, ASCII)).then(function() {
                    var expected_signing_ms = 6000;
                    if (btchip_dev.features.quickerVersion) expected_signing_ms *= 0.74;
                    var restart_countdown = function() {
                        var elapsed_signing_ms = 0
                        $scope.hardware_progress = 1;
                        var countdown = $interval(function() {
                            elapsed_signing_ms += 100;
                            $scope.hardware_progress = Math.min(100, Math.round(100*elapsed_signing_ms/expected_signing_ms));
                            if ($scope.hardware_progress >= 100) {
                                // second login is faster because pubkey is already derived:
                                expected_signing_ms = 4500;
                                if (btchip_dev.features.quickerVersion) expected_signing_ms *= 0.74;
                                $interval.cancel(countdown);
                            }
                        }, 100);
                    };
                    restart_countdown();
                    $scope.logging_in = true;
                    btchip_dev.app.getWalletPublicKey_async('').then(function(result) {
                        wallets.login_btchip($scope, btchip_dev, result, restart_countdown).finally(function() {
                            $scope.logging_in = false;
                        });
                    }).fail(function(error) {
                        $scope.logging_in = false;
                        btchip_dev.dongle.disconnect_async();
                        notices.makeNotice("error", error);
                    });
                }).fail(function(error) {
                    btchip_dev.dongle.disconnect_async();
                    if (error.indexOf("6982") >= 0) {
                        notices.makeNotice("error", gettext("Invalid PIN"));
                    } else if (error.indexOf("63c2") >= 0) {
                        notices.makeNotice("error", gettext("Invalid PIN, 2 retries left"));
                    } else if (error.indexOf("63c1") >= 0) {
                        notices.makeNotice("error", gettext("Invalid PIN, 1 retry left"));
                    } else if (error.indexOf("63c0") >= 0) {
                        notices.makeNotice("error", gettext("Invalid PIN, dongle wiped"));
                    } else if (error.indexOf("6985") >= 0) {
                        notices.makeNotice("error", gettext("Dongle is not set up"));
                    } else if (error.indexOf("6faa") >= 0) {
                        notices.makeNotice("error", gettext("Dongle is locked - reconnect the dongle and retry"));
                    } else {
                        notices.makeNotice("error", error);
                    }
                });
            });
        });
    };

    var template = gettext("{hardware_wallet_name} Login");
    btchip.getDevice('retry').then(function(btchip) {
        btchip.dongle.disconnect_async();
        state.hw_detected = template.replace('{hardware_wallet_name}', 'BTChip');
    });

    trezor.getDevice('retry', true).then(function(trezor) {
        state.hw_detected = template.replace('{hardware_wallet_name}', 'TREZOR');
        trezor_dev = trezor;
    })

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

    var pin_attempts_left = 3;
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
                return crypto.decrypt(state.encrypted_seed, password).then(function(decoded) {
                    if(decoded && JSON.parse(decoded).seed) {
                        gaEvent('Login', 'PinLoginSucceeded');
                        var parsed = JSON.parse(decoded);
                        if (!parsed.path_seed) {
                            return mnemonics.toSeed(parsed.mnemonic, 'greenaddress_path').then(function(path_seed) {
                                parsed.path_seed = path_seed;
                                crypto.encrypt(JSON.stringify(parsed), password).then(function(encrypted) {
                                    storage.set('encrypted_seed', encrypted);
                                })
                                var path = mnemonics.seedToPath(path_seed);
                                return $q.when(Bitcoin.HDWallet.fromSeedHex(parsed.seed, cur_net)).then(function(hdwallet) {
                                    hdwallet.seed_hex = parsed.seed;
                                    return wallets.login($scope, hdwallet, state.mnemonic, false, false, path_seed);
                                });
                            }, undefined, function(progress) {
                                state.seed_progress = progress;
                            });
                        } else {
                            return $q.when(Bitcoin.HDWallet.fromSeedHex(parsed.seed, cur_net)).then(function(hdwallet) {
                                hdwallet.seed_hex = parsed.seed;
                                return wallets.login($scope, hdwallet, parsed.mnemonic, false, false, parsed.path_seed);
                            });
                        }
                    } else {
                        gaEvent('Login', 'PinLoginFailed', 'Wallet decryption failed');
                        state.login_error = true;
                        notices.makeNotice('error', gettext('Wallet decryption failed'));
                    }
                });
            }, function(e) {
                gaEvent('Login', 'PinLoginFailed', e.desc);
                var suffix = '';
                if (e.uri == "http://greenaddressit.com/error#password") {
                    pin_attempts_left -= 1;
                    if (pin_attempts_left > 0) {
                        suffix = '; ' + gettext('%s attempts left.').replace('%s', pin_attempts_left);
                    } else {
                        suffix = '; ' + gettext('0 attempts left - PIN removed.').replace('%s', pin_attempts_left);
                        storage.remove('pin_ident');
                        storage.remove('encrypted_seed');
                        state.has_pin = false;
                        state.toggleshowpin = true;
                        delete use_pin_data.pin;
                    }
                }
                notices.makeNotice('error', (e.desc || e) + suffix);
                state.login_error = true;
            });
    }
}]);
