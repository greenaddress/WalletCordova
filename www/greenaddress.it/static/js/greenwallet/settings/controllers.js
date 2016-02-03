angular.module('greenWalletSettingsControllers',
    ['greenWalletServices', 'greenWalletSettingsDirectives'])
.controller('TwoFactorSetupController', ['$scope', '$modal', 'notices', 'focus', 'tx_sender', 'wallets', 'gaEvent', '$q', 'clipboard',
        function TwoFactorSetupController($scope, $modal, notices, focus, tx_sender, wallets, gaEvent, $q, clipboard) {
    if (!wallets.requireWallet($scope, true)) return;  // dontredirect=true because this cocntroller is reused in signup
    var twofactor_state = $scope.twofactor_state = {
        twofactor_type: 'email'
    }
    var updating = {email: true, sms: true, phone: true, gauth: true};
    var update_wallet = function() {
        wallets.getTwoFacConfig($scope, true).then(function(data) {
            if (data.gauth) {
                twofactor_state.twofac_gauth_switch = true;
            } else {
                twofactor_state.twofac_gauth_switch = false;
                twofactor_state.google_secret_url = data.gauth_url;
                twofactor_state.google_secret_key = data.gauth_url.split('=')[1];
            }
            twofactor_state.twofac_email_switch = data.email;
            $scope.wallet.twofac_email_switch = data.email;  // used by notification and nLockTime settings
            twofactor_state.twofac_sms_switch = data.sms;
            twofactor_state.twofac_phone_switch = data.phone;
        }, function(err) {
            notices.makeNotice('error', 'Error fetching two factor authentication configuration: ' + err.args[1]);
            twofactor_state.twofactor_type = 'error';
        });
    };
    update_wallet();
    $scope.gauth_qr_modal = function() {
        gaEvent('Wallet', 'GoogleAuthQRModal');
        $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_gauth_qr.html',
            scope: $scope
        });
    };
    $scope.copy_to_clipboard = function(data) {
        clipboard.copy(data).then(
            function(text){
                notices.makeNotice('success', text);
            },
            function(error){
                notices.makeNotice('error', error);
            }
        );
    };
    $scope.show_gauth = function() {
        gaEvent('Wallet', 'GoogleAuth2FATabClicked');
        twofactor_state.twofactor_type = 'gauth';
    };
    $scope.show_email_auth = function() {
        gaEvent('Wallet', 'Email2FATabClicked');
        twofactor_state.twofactor_type = 'email';
    };
    $scope.show_sms_auth = function() {
        gaEvent('Wallet', 'SMS2FATabClicked');
        twofactor_state.twofactor_type = 'sms';
    };
    $scope.show_phone_auth = function() {
        gaEvent('Wallet', 'Phone2FATabClicked');
        twofactor_state.twofactor_type = 'phone';
    };
    $scope.enable_twofac_gauth = function() {
        notices.setLoadingText("Validating code");
        return tx_sender.call('http://greenaddressit.com/twofactor/enable_gauth', twofactor_state.twofac_gauth_code, $scope.twofac_data).then(
            function() {
                gaEvent('Wallet', 'EnableGauth2FASuccessful');
                notices.makeNotice('success', 'Enabled Google Authenticator');
                twofactor_state.twofac_gauth_code = '';
                twofactor_state.twofac_gauth_switch = true;
                update_wallet();
            }, function(err) {
                twofactor_state.twofac_gauth_code = '';
                gaEvent('Wallet', 'EnableGauth2FAFailed', err.args[1]);
                notices.makeNotice('error', err.args[1]);
                return $q.reject(err);
            });
    };
    $scope.disable_2fa = function(type, twofac_data) {
        notices.setLoadingText("Validating code");
        if (type == 'gauth') {
            return tx_sender.call('http://greenaddressit.com/twofactor/disable_gauth', twofac_data).then(
                function() {
                    gaEvent('Wallet', 'DisableGauth2FASuccessful');
                    twofactor_state.disable_2fa_code = '';
                    notices.makeNotice('success', 'Disabled Google Authenticator');
                    twofactor_state.twofac_gauth_switch = false;
                    update_wallet();  // new secret required for re-enabling
                }, function(err) {
                    gaEvent('Wallet', 'DisableGauth2FAFailed', err.args[1]);
                    notices.makeNotice('error', err.args[1]);
                    return $q.reject(err);
                })
        } else if (type == 'email') {
            return tx_sender.call('http://greenaddressit.com/twofactor/disable_email', twofac_data).then(
                function() {
                    gaEvent('Wallet', 'DisableEmail2FASuccessful');
                    twofactor_state.disable_2fa_code = '';
                    notices.makeNotice('success', 'Disabled email two factor authentication');
                    twofactor_state.twofac_email_switch = false;
                    twofactor_state.email_set = false;
                    update_wallet();
                }, function(err) {
                    gaEvent('Wallet', 'DisableEmail2FAFailed', err.args[1]);
                    notices.makeNotice('error', err.args[1]);
                    return $q.reject(err);
                })
        } else if (type == 'sms') {
            return tx_sender.call('http://greenaddressit.com/twofactor/disable_sms', twofac_data).then(
                function() {
                    gaEvent('Wallet', 'DisableSMS2FASuccessful');
                    twofactor_state.disable_2fa_code = '';
                    notices.makeNotice('success', 'Disabled SMS two factor authentication');
                    twofactor_state.twofac_sms_switch = false;
                    twofactor_state.sms_set = false;
                    update_wallet();
                }, function(err) {
                    gaEvent('Wallet', 'DisableSMS2FAFailed', err.args[1]);
                    notices.makeNotice('error', err.args[1]);
                    return $q.reject(err);
                })
        } else if (type == 'phone') {
            return tx_sender.call('http://greenaddressit.com/twofactor/disable_phone', twofac_data).then(
                function() {
                    gaEvent('Wallet', 'DisablePhone2FASuccessful');
                    twofactor_state.disable_2fa_code = '';
                    notices.makeNotice('success', 'Disabled phone call two factor authentication');
                    twofactor_state.twofac_phone_switch = false;
                    twofactor_state.phone_set = false;
                    update_wallet();
                }, function(err) {
                    gaEvent('Wallet', 'DisablePhone2FAFailed', err.args[1]);
                    notices.makeNotice('error', err.args[1]);
                    return $q.reject(err);
                })
        }
    };
    $scope.start_enabling_email = function(twofac_data) {
        if (twofactor_state.enabling_email) return;
        twofactor_state.enabling_email = true;
        return tx_sender.call('http://greenaddressit.com/twofactor/init_enable_email', twofactor_state.new_twofac_email, twofac_data).then(
            function() {
                gaEvent('Wallet', 'StartEnablingEmail2FASuccessful');
                twofactor_state.email_set = true;
            }, function(err) {
                gaEvent('Wallet', 'StartEnablingEmail2FAFailed', err.args[1]);
                notices.makeNotice('error', err.args[1]);
            }).finally(function() {
                twofactor_state.enabling_email = false;
            });
    };
    $scope.cancel_twofac_email = function() {
        twofactor_state.email_set = false;
        twofactor_state.data_email = undefined;
    };
    $scope.enable_twofac_email = function() {
        notices.setLoadingText("Validating code");
        var suffix = '_twofac', arg = $scope.twofac_data;
        if ($scope.wallet.signup) {
            suffix = '';
            arg = twofactor_state.twofac_email_code;
        }
        var onSuccess = function() {
            gaEvent('Wallet', 'EnableEmail2FASuccessful');
            notices.makeNotice('success', 'Enabled email two factor authentication');
            twofactor_state.twofac_email_code = '';
            twofactor_state.twofac_email_switch = true;
            update_wallet();
        };
        var onFail = function(err) {
            gaEvent('Wallet', 'EnableEmail2FAFailed', err.args[1]);
            twofactor_state.twofac_email_code = '';
            notices.makeNotice('error', err.args[1]);
            return $q.reject(err);
        };
        return tx_sender.call('http://greenaddressit.com/twofactor/enable_email'+suffix, arg).then(
            onSuccess,
            function(err) {
                if ($scope.wallet.signup && err.args[0] == "http://greenaddressit.com/error#alreadyexists") {
                    return $modal.open({
                        templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_reset_email.html'
                    }).result.then(function() {
                        return tx_sender.call('http://greenaddressit.com/twofactor/enable_email',
                            arg, twofactor_state.new_twofac_email).then(onSuccess, onFail);
                    });
                } else {
                    onFail(err);
                }
            });
    };
    $scope.start_enabling_sms = function(twofac_data) {
        if (twofactor_state.enabling_sms) return;
        twofactor_state.enabling_sms = true;
        return tx_sender.call('http://greenaddressit.com/twofactor/init_enable_sms', twofactor_state.new_twofac_sms, twofac_data).then(
            function() {
                gaEvent('Wallet', 'StartEnablingSMS2FASuccessful');
                twofactor_state.sms_set = true;
            }, function(err) {
                gaEvent('Wallet', 'StartEnablingSMS2FAFailed', err.args[1]);
                notices.makeNotice('error', err.args[1]);
                return $q.reject(err);
            }).finally(function() {
                twofactor_state.enabling_sms = false;
            });
    };
    $scope.cancel_twofac_sms = function() {
        twofactor_state.sms_set = false;
    };
    $scope.enable_twofac_sms = function() {
        notices.setLoadingText("Validating code");
        return tx_sender.call('http://greenaddressit.com/twofactor/enable_sms', twofactor_state.twofac_sms_code).then(
            function() {
                gaEvent('Wallet', 'EnableSMS2FASuccessful');
                notices.makeNotice('success', 'Enabled SMS two factor authentication');
                twofactor_state.twofac_sms_code = '';
                twofactor_state.twofac_sms_switch = true;
                update_wallet();
            }, function(err) {
                twofactor_state.twofac_sms_code = '';
                gaEvent('Wallet', 'EnableSMS2FAFailed', err.args[1]);
                notices.makeNotice('error', err.args[1]);
            });
    };
    $scope.start_enabling_phone = function(twofac_data) {
        if (twofactor_state.enabling_phone) return;
        twofactor_state.enabling_phone = true;
        return tx_sender.call('http://greenaddressit.com/twofactor/init_enable_phone', twofactor_state.new_twofac_phone, twofac_data).then(
            function() {
                gaEvent('Wallet', 'StartEnablingPhone2FASuccessful');
                twofactor_state.phone_set = true;
            }, function(err) {
                gaEvent('Wallet', 'StartEnablingPhone2FAFailed', err.args[1]);
                notices.makeNotice('error', err.args[1]);
            }).finally(function() {
                twofactor_state.enabling_phone = false;
            });;
    };
    $scope.cancel_twofac_phone = function() {
        twofactor_state.phone_set = false;
    };
    $scope.enable_twofac_phone = function() {
        notices.setLoadingText("Validating code");
        return tx_sender.call('http://greenaddressit.com/twofactor/enable_phone', twofactor_state.twofac_phone_code).then(
            function() {
                gaEvent('Wallet', 'EnablePhone2FASuccessful');
                notices.makeNotice('success', 'Enabled phone two factor authentication');
                twofactor_state.twofac_phone_code = '';
                twofactor_state.twofac_phone_switch = true;
                update_wallet();
            }, function(err) {
                twofactor_state.twofac_phone_code = '';
                gaEvent('Wallet', 'EnablePhone2FAFailed', err.args[1]);
                notices.makeNotice('error', err.args[1]);
            });
    };

    var setup_2fa = function(type) {
        $scope.$watch('twofactor_state.twofac_'+type+'_switch', function(newValue, oldValue) {
            if ($scope.wallet.signup) return;
            if (newValue === oldValue || $scope.twofactor_state['toggling_'+type] == 'initial'
                || $scope.twofactor_state['toggling_'+type] == 'old_2fa') return;
            if (updating[type]) { updating[type] = false; return; }
            if ($scope.twofactor_state['toggling_'+type] == 'disabling' && newValue == true) return;
            if ($scope.twofactor_state['toggling_'+type] == 'disabling' || $scope.twofactor_state['toggling_'+type] == 'enabling' ||
                $scope.twofactor_state['toggling_'+type] == 'enabling_email_2nd') {
                if (!$scope.wallet.signup && type == 'email' && $scope.twofactor_state['toggling_'+type] == 'enabling') {
                    // email toggling in settings changes twice on enabling - first to false,
                    // then back to true, because there is no initial state
                    $scope.twofactor_state['toggling_'+type] = 'enabling_email_2nd';
                } else {
                    $scope.twofactor_state['toggling_'+type] = false;
                }
                return;
            }
            $scope.twofactor_state['twofac_'+type+'_switch'] = oldValue;
            if (oldValue) { // disabling
                $scope.twofactor_state['toggling_'+type] = 'disabling';
                $scope.twofactor_state.twofactor_type = type;
                wallets.get_two_factor_code($scope, 'disable_2fa', {method: type}).then(function(twofac_data) {
                    return $scope.disable_2fa(type, twofac_data)
                }).catch(function() {
                    $scope.twofactor_state['toggling_'+type] = false;
                });
                return;
            }
            // step 1 - just show the inputs
            if (type == 'email') {
                $scope.twofactor_state['toggling_'+type] = 'enabling';
            } else {
                $scope.twofactor_state['toggling_'+type] = 'old_2fa';
            }
            wallets.get_two_factor_code($scope, 'enable_2fa', {method: type}).then(function(twofac_data) {
                if (type == 'email') {
                    $scope.twofac_data = twofac_data;
                    return $scope['enable_twofac_'+type]();
                } else {
                    return tx_sender.call('http://greenaddressit.com/twofactor/request_proxy', type, twofac_data).then(function(data) {
                        $scope.twofactor_state['toggling_'+type] = 'initial';
                        $scope.twofac_data = {'method': 'proxy', 'code': data};
                    }, function(err) {
                        notices.makeNotice('error', err.args[1]);
                        return $q.reject(err);
                    });
                }
            }).catch(function() {
                $scope.twofactor_state['toggling_'+type] = false;
            });
        });

        $scope['submit_'+type] = function() {
            if (type == 'gauth' || $scope.twofactor_state[type+'_set']) {  // already set - enable
                $scope.twofactor_state['toggling_'+type] = 'enabling';
                $scope['enable_twofac_'+type]().catch(function() { $scope.twofactor_state['toggling_'+type] = 'initial'; } );
            } else {  // start enabling (set the email address/phone number)
                $scope['start_enabling_'+type]($scope.twofac_data);
            }
        };
    };
    setup_2fa('email');
    setup_2fa('sms');
    setup_2fa('phone');
    setup_2fa('gauth');
}]).controller('SettingsController', ['$scope', '$q', 'wallets', 'tx_sender', 'notices', '$modal', 'gaEvent', 'storage', '$location', '$timeout', 'bip38', 'mnemonics', 'btchip', 'trezor', 'hw_detector',
        function SettingsController($scope, $q, wallets, tx_sender, notices, $modal, gaEvent, storage, $location, $timeout, bip38, mnemonics, btchip, trezor, hw_detector) {
    if (!wallets.requireWallet($scope)) return;
    var userfriendly_blocks = function(num) {
        return gettext("(about %s days: 1 day ≈ 144 blocks)").replace("%s", Math.round(num/144));
    }
    var settings = $scope.settings = {
        replace_by_fee: $scope.wallet.appearance.replace_by_fee,
        noLocalStorage: storage.noLocalStorage,
        unit: $scope.wallet.unit,
        pricing_source: $scope.wallet.fiat_currency + '|' + $scope.wallet.fiat_exchange,
        notifications: angular.copy($scope.wallet.appearance.notifications_settings || {}),
        language: LANG,
        updating_display_fiat: false,
        nlocktime: {
            blocks: $scope.wallet.nlocktime_blocks,
            blocks_new: $scope.wallet.nlocktime_blocks,
            update: function() {
                this.updating_nlocktime_blocks = true;
                var that = this;
                wallets.get_two_factor_code($scope, 'change_nlocktime', {'value': that.blocks_new}).then(function(twofac_data) {
                    return tx_sender.call('http://greenaddressit.com/login/set_nlocktime', that.blocks_new, twofac_data).then(function() {
                        $scope.wallet.nlocktime_blocks = that.blocks = that.blocks_new;
                        notices.makeNotice('success', gettext('nLockTime settings updated successfully'));
                    }, function(err) {
                        notices.makeNotice('error', err.args[1]);
                    });
                }).finally(function() { that.updating_nlocktime_blocks = false; });
            }
        },
        nfcmodal: function() {
            gaEvent('Wallet', 'SettingsNfcModal');
            mnemonics.validateMnemonic($scope.wallet.mnemonic).then(function(bytes) {
                $scope.nfc_bytes = bytes;
                $scope.nfc_mime = 'x-gait/mnc';
                $modal.open({
                    templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signup_nfc_modal.html',
                    scope: $scope,
                    controller: 'NFCController'
                });
            });
        },
        nfcmodal_encrypted: function() {
            gaEvent('Wallet', 'SettingsNfcModal');
            mnemonics.validateMnemonic($scope.wallet.mnemonic).then(function(bytes) {
                bip38.encrypt_mnemonic_modal($scope, bytes).then(function(mnemonic_encrypted) {
                    mnemonics.validateMnemonic(mnemonic_encrypted).then(function(bytes_encrypted) {
                        $scope.nfc_bytes = bytes_encrypted;
                        $scope.nfc_mime = 'x-ga/en';
                        $modal.open({
                            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signup_nfc_modal.html',
                            scope: $scope,
                            controller: 'NFCController'
                        });
                    });
                });
            });
        },
        usbmodal: function() {
            var is_chrome_app = window.chrome && chrome.storage;
            if (is_chrome_app) {
                hw_detector.waitForHwWallet().then(function() {
                    trezor.getDevice(true).then(function() {
                        trezor.recovery($scope.wallet.mnemonic);
                    }, function() {
                        btchip.setupSeed($scope.wallet.mnemonic);
                    });
                })
            } else {
                trezor.recovery($scope.wallet.mnemonic);
            }
        },
        expiring_soon_modal: function() {
            gaEvent('Wallet', 'ExpiringSoonModal');
            tx_sender.call('http://greenaddressit.com/txs/upcoming_nlocktime').then(function(data) {
                $scope.soon_nlocktimes = data;
                $scope.soon_nlocktimes.estimate_days = function(nlocktime_at) {
                    var remaining_blocks = nlocktime_at - this.cur_block;
                    if (remaining_blocks <= 0) return gettext('Already expired');
                    else return gettext('in about %s days').replace('%s', Math.round(remaining_blocks/144));
                };
                $modal.open({
                    templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_expiring_soon.html',
                    scope: $scope
                });
            }, function(err) {
                notices.makeNotice('error', err.args[1]);
            });
        },
        send_nlocktime: function() {
            var that = this;
            that.sending_nlocktime = true;
            gaEvent('Wallet', 'SendNlocktimeByEmail');
            tx_sender.call('http://greenaddressit.com/txs/send_nlocktime').then(function(data) {
                notices.makeNotice('success', gettext('Email sent'));
            }, function(err) {
                notices.makeNotice('error', err.args[1]);
            }).finally(function() { that.sending_nlocktime = false; });
        }
    };
    $scope.settings.available_units = ['BTC', 'mBTC', 'µBTC', 'bits'];
    tx_sender.call('http://greenaddressit.com/login/available_currencies').then(function(data) {
        $scope.settings.pricing_sources = [];
        for (var i = 0; i < data.all.length; i++) {
            var currency = data.all[i];
            for (var exchange in data.per_exchange) {
                if (data.per_exchange[exchange].indexOf(currency) != -1) {
                    $scope.settings.pricing_sources.push({currency: currency, exchange: exchange});
                }
            }
        }
    });
    $scope.$watch('settings.nlocktime.blocks_new', function(newValue, oldValue) {
        settings.nlocktime.blocks_userfriendly = userfriendly_blocks(settings.nlocktime.blocks_new);
    });
    $scope.$watch('wallet.twofac.email_addr', function(newValue, oldValue) {
        settings.new_email = newValue;
    });
    if (!settings.currency) {
        $scope.$on('first_balance_updated', function() {
            settings.pricing_source = $scope.wallet.fiat_currency + '|' + $scope.wallet.fiat_exchange;
        })
    }
    var ignoreLangChange = false;
    $scope.$watch('settings.language', function(newValue, oldValue) {
        if (newValue == oldValue) return;
        if (ignoreLangChange) { ignoreLangChange = false; return; }
        settings.language = oldValue;
        ignoreLangChange = true;  // don't ask for logout on change back to previous lang
        var is_chrome_app = window.chrome && chrome.storage;
        wallets.askForLogout($scope, gettext('You need to log out for language changes to be applied.')).then(function() {
            if (is_chrome_app) {
                storage.set('language', newValue);
                chrome.runtime.sendMessage({changeLang: true, lang: newValue});
            } else if (window.cordova) {
                plugins.appPreferences.store(function() {
                    window.location.href = BASE_URL + '/' + newValue + '/' + 'wallet.html';
                }, function(error) {
                    notices.makeNotice('error', gettext('Error changing language:') + ' ' + error);
                }, 'language', newValue);
            } else {
                window.location.href = '/'+newValue+'/wallet';
            }
        });
    });
    $scope.$watch('settings.pricing_source', function(newValue, oldValue) {
        var currency = newValue.split('|')[0];
        var exchange = newValue.split('|')[1];
        if (oldValue !== newValue && !settings.updating_pricing_source &&
                (currency != $scope.wallet.fiat_currency || exchange != $scope.wallet.fiat_exchange)) {
            // no idea why oldValue-on-error handling doesn't work without $timeout here
            $timeout(function() { settings.pricing_source = oldValue; });
            settings.updating_pricing_source = true;
            var update = function() {
                tx_sender.call('http://greenaddressit.com/login/set_pricing_source', currency, exchange).then(function() {
                    gaEvent('Wallet', 'PricingSourceChanged', newValue);
                    $scope.wallet.fiat_currency = currency;
                    $scope.wallet.fiat_exchange = exchange;
                    $scope.wallet.update_balance();
                    tx_sender.call("http://greenaddressit.com/login/get_spending_limits").then(function(data) {
                        // we reset limits if we change currency source while limits are fiat
                        $scope.wallet.limits.per_tx = data.per_tx;
                        $scope.wallet.limits.total = data.total;
                    });
                    settings.pricing_source = newValue;
                    settings.updating_pricing_source = false;
                }).catch(function(err) {
                    settings.updating_pricing_source = false;
                    if (err.args[0] == "http://greenaddressit.com/error#exchangecurrencynotsupported") {
                        gaEvent('Wallet', 'CurrencyNotSupportedByExchange');
                        notices.makeNotice('error', gettext('{1} supports only the following currencies: {2}')
                            .replace('{1}', exchanges[exchange])
                            .replace('{2}', err.detail.supported));
                    } else {
                        gaEvent('Wallet', 'PricingSourceChangeFailed', err.args[1]);
                        notices.makeNotice('error', err.args[1]);
                    }
                });
            };
            if ($scope.wallet.limits.is_fiat && parseInt($scope.wallet.limits.total)) {
                $modal.open({
                    templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_tx_limits_fiat_warning.html'
                }).result.then(update, function() { settings.updating_pricing_source = false; });
            } else {
                update();
            }


        }
    });
    $scope.$watch('settings.currency', function(newValue, oldValue) {
        if (oldValue !== newValue && !settings.updating_currency && newValue != $scope.wallet.fiat_currency) {
            settings.currency = oldValue;
            settings.updating_currency = true;
            tx_sender.call('http://greenaddressit.com/login/set_currency', newValue).then(function() {
                gaEvent('Wallet', 'CurrencyChanged', newValue);
                $scope.wallet.fiat_currency = newValue;
                $scope.wallet.update_balance();
                settings.currency = newValue;
                settings.updating_currency = false;
            }).catch(function(err) {
                settings.updating_currency = false;
                if (err.args[0] == "http://greenaddressit.com/error#exchangecurrencynotsupported") {
                    gaEvent('Wallet', 'CurrencyNotSupportedByExchange');
                    notices.makeNotice('error', gettext('{1} supports only the following currencies: {2}')
                        .replace('{1}', exchanges[settings.exchange])
                        .replace('{2}', err.detail.supported));
                } else {
                    gaEvent('Wallet', 'CurrencyChangeFailed', err.args[1]);
                    notices.makeNotice('error', err.args[1]);
                }
            });
        }
    });
    $scope.$watch('settings.replace_by_fee', function(newValue, oldValue) {
        if (oldValue !== newValue && !settings.replace_by_fee_updating &&
                // avoid infinite loop by checking for post-update value change:
                newValue != $scope.wallet.appearance.replace_by_fee) {
            settings.replace_by_fee_updating = true;
            settings.replace_by_fee = oldValue;  // set to old until really updated
            wallets.updateAppearance(
                $scope, 'replace_by_fee', newValue
            ).then(function() {
                settings.replace_by_fee_updating = false;
                settings.replace_by_fee = newValue;
            }).finally(function() {
                settings.replace_by_fee_updating = false;
            });
        }
    });
    $scope.$watch('settings.exchange', function(newValue, oldValue) {
        if (oldValue !== newValue && !settings.updating_exchange && newValue != $scope.wallet.fiat_exchange) {
            settings.exchange = oldValue;
            settings.updating_exchange = true;
            tx_sender.call('http://greenaddressit.com/login/set_exchange', newValue).then(function() {
                gaEvent('Wallet', 'ExchangeChanged', newValue);
                $scope.wallet.fiat_exchange = newValue;
                $scope.wallet.update_balance();
                settings.exchange = newValue;
                settings.updating_exchange = false;
            }).catch(function(err) {
                settings.updating_exchange = false;
                if (err.args[0] == "http://greenaddressit.com/error#exchangecurrencynotsupported") {
                    gaEvent('Wallet', 'CurrencyNotSupportedByExchange');
                    notices.makeNotice('error', gettext('{1} supports only the following currencies: {2}')
                        .replace('{1}', exchanges[newValue])
                        .replace('{2}', err.detail.supported));
                } else {
                    gaEvent('Wallet', 'ExchangeChangeFailed', err.args[1]);
                    notices.makeNotice('error', err.args[1]);
                }
            });
        }
    });
    var watchNotificationsEmail = function(inout, eventprefix) {
        $scope.$watch('settings.notifications.email_'+inout, function(newValue, oldValue) {
            if (newValue === oldValue) return;
            if (!settings['updating_ntf_email_'+inout] && newValue !==
                        ($scope.wallet.appearance.notifications_settings||{})['email_'+inout]) {
                var notificationsNewValue = angular.copy(settings.notifications);
                settings.notifications['email_'+inout] = oldValue;
                settings['updating_ntf_email_'+inout] = true;
                wallets.updateAppearance($scope, 'notifications_settings', notificationsNewValue).then(function() {
                    gaEvent('Wallet', eventprefix+(newValue?'Enabled':'Disabled'));
                    settings.notifications['email_'+inout] = newValue;
                    settings['updating_ntf_email_'+inout] = false;
                }).catch(function(err) {
                    gaEvent('Wallet', eventprefix+(newValue?'Enable':'Disable')+'Failed', err.args[1]);
                    notices.makeNotice('error', err.args[1]);
                    settings['updating_ntf_email_'+inout] = false;
                });
            }
        });
    };
    watchNotificationsEmail('incoming', 'EmailIncomingNotifications');
    watchNotificationsEmail('outgoing', 'EmailOutgoingNotifications');
    $scope.$watch('settings.unit', function(newValue, oldValue) {
        if (oldValue !== newValue && !settings.updating_unit && newValue != $scope.wallet.appearance.unit) {
            settings.unit = oldValue;
            settings.updating_unit = true;
            wallets.updateAppearance($scope, 'unit', newValue).then(function() {
                gaEvent('Wallet', 'UnitChanged', newValue);
                settings.unit = $scope.wallet.unit = newValue;
                settings.updating_unit = false;
            }).catch(function(err) {
                gaEvent('Wallet', 'UnitChangeFailed', err.args[1]);
                notices.makeNotice('error', err.args[1]);
                settings.updating_unit = false;
            });
        }
    });
    $scope.enable_link_handler = function() {
        try {
            navigator.registerProtocolHandler('bitcoin', 'https://'+window.location.hostname+'/uri/?uri=%s', 'GreenAddress.It');
            notices.makeNotice('success', gettext('Sent handler registration request'));
        } catch(e) {
            notices.makeNotice('error', e.toString());
        }
    }
    $scope.show_encrypted_mnemonic = function() {
        gaEvent('Wallet', 'ShowEncryptedMnemonic');
        mnemonics.fromMnemonic($scope.wallet.mnemonic).then(function(data) {
            bip38.encrypt_mnemonic_modal($scope, data).then(function(mnemonic_encrypted) {
                $scope.mnemonic_encrypted = mnemonic_encrypted;
                $modal.open({
                    templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_mnemonic.html',
                    scope: $scope
                });
            });
        });
    };
    $scope.show_mnemonic = function() {
        gaEvent('Wallet', 'ShowMnemonic');
        $scope.mnemonic_encrypted = undefined;
        $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_mnemonic.html',
            scope: $scope
        });
    };
    $scope.remove_account = function() {
        gaEvent('Wallet', 'RemoveAccountClicked');
        if ($scope.wallet.final_balance != 0) {
            notices.makeNotice('error', gettext("Cannot remove an account with non-zero balance"))
            return;
        }
        $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_remove_account.html',
        }).result.then(function() {
            wallets.get_two_factor_code($scope, 'remove_account', {}).then(function(twofac_data) {
                return tx_sender.call('http://greenaddressit.com/login/remove_account', twofac_data).then(function() {
                    tx_sender.logout();
                    storage.remove('pin_ident');
                    storage.remove('pin_chaincode');
                    storage.remove('encrypted_seed');
                    $location.path('/');
                }).catch(function(err) {
                    notices.makeNotice('error', err.args[1]);
                    return $q.reject(err);
                });
            });
        });
    };
    $scope.set_new_email = function() {
        if ($scope.wallet.twofac.email) {
            notices.makeNotice('error', gettext("You can't change your email address while you have email 2FA enabled"));
            return;
        }
        settings.setting_email = true;
        wallets.get_two_factor_code($scope, 'set_email', {'address': settings.new_email}).then(function(twofac_data) {
            return tx_sender.call('http://greenaddressit.com/twofactor/set_email', settings.new_email, twofac_data).then(function() {
                wallets.getTwoFacConfig($scope, true);  // refresh twofac config
                notices.makeNotice('success', gettext('Email sent'));
            }).catch(function(err) {
                notices.makeNotice('error', err.args[1]);
                return $q.reject(err);
            });
        }).finally(function() { settings.setting_email = false; });
    };
    $scope.confirm_email = function() {
        tx_sender.call('http://greenaddressit.com/twofactor/activate_email', settings.email_confirmation_code).then(function() {
            wallets.getTwoFacConfig($scope, true);  // refresh twofac config
            notices.makeNotice('success', gettext('Email confirmed'))
        }).catch(function(err) {
            notices.makeNotice('error', err.args[1]);
        });
    };
}]).controller('PrivacyController', ['$scope', 'tx_sender', 'wallets', 'notices',
        function PrivacyController($scope, tx_sender, wallets, notices) {
    if (!wallets.requireWallet($scope, true)) return;   // dontredirect=true because one redirect in SettingsController is enough

    $scope.privacy = {
        'updating_send_me': false,
        'send_me': ''+$scope.wallet.privacy.send_me,
        'updating_show_as_sender': false,
        'show_as_sender': ''+$scope.wallet.privacy.show_as_sender
    };
    var init_changer = function(key) {
        $scope.$watch('privacy.' + key, function(newValue, oldValue) {
            if (newValue == oldValue || newValue == $scope.wallet.privacy[key]) return;
            var upkey = 'updating_' + key;
            $scope.privacy[upkey] = true;
            $scope.privacy[key] = oldValue;
            tx_sender.call('http://greenaddressit.com/login/change_settings', 'privacy.' + key, parseInt(newValue)).then(function() {
                $scope.wallet.privacy[key] = newValue;
                $scope.privacy[upkey] = false;
                $scope.privacy[key] = newValue;
            }, function(err) {
                notices.makeNotice('error', err.args[1]);
                $scope.privacy[upkey] = false;
            });
        });
    };
    init_changer('send_me');
    init_changer('show_as_sender');
}]).controller('AddressBookController', ['$scope', 'tx_sender', 'notices', 'focus', 'wallets', '$location', 'gaEvent', '$rootScope', '$routeParams', 'addressbook', 'qrcode',
        function AddressBookController($scope, tx_sender, notices, focus, wallets, $location, gaEvent, $rootScope, $routeParams, addressbook, qrcode) {
    // dontredirect=false here because address book is now outside settings,
    // though it's also used from inside SendController, hence the $location.url() check
    if (!wallets.requireWallet($scope, $location.url().indexOf('/address-book') != -0)) return;
    $routeParams.page = $routeParams.page || 1;
    $routeParams.page = parseInt($routeParams.page);
    $scope.route = $routeParams;
    $scope.addressbook = addressbook;
    addressbook.load($scope, $routeParams);
    $scope.read_qr_code = function($event) {
        gaEvent('Wallet', 'AddressBookReadQrCode');
        qrcode.scan($scope, $event, '_addrbook').then(function(text) {
            gaEvent('Wallet', 'AddressBookReadQrCodeSuccessful');
            $rootScope.safeApply(function() {
                if (text.indexOf('bitcoin:') == 0) {
                    text = text.slice('bitcoin:'.length);
                }
                addressbook.new_item.address = text;
            });
        }, function(error) {
            gaEvent('Wallet', 'AddressBookQrCodeFailed', error);
            notices.makeNotice('error', error);
        });
    };
    $scope.stop_scanning_qr_code = function() {
        qrcode.stop_scanning($scope);
    };
    $scope.add = function() {
        gaEvent('Wallet', 'AddressBookNewItemStarted');
        addressbook.new_item = {name: '', address: '', type: 'address'};
        focus('addrbook_new_item');
    };
    $scope.delete = function(address) {
        gaEvent('Wallet', 'AddressBookDeleteItem');
        tx_sender.call('http://greenaddressit.com/addressbook/delete_entry', address).then(function() {
            var filtered_items = [];
            angular.forEach(addressbook.items, function(value) {
                if (value.address != address) {
                    filtered_items.push(value);
                }
            });
            addressbook.items = filtered_items;
            addressbook.init_partitions();
            addressbook.num_pages = Math.ceil(addressbook.items.length / 20);
            addressbook.populate_csv();
        });
    };
    $scope.rename = function(address, name, type) {
        if (type == 'subaccount') {
            var pointer, i;
            for (i = 0; i < $scope.wallet.subaccounts.length; i++) {
                var account = $scope.wallet.subaccounts[i];
                if (account.receiving_id == address) {
                    pointer = $scope.wallet.subaccounts[i].pointer;
                    break;
                }
            }
            var d = tx_sender.call('http://greenaddressit.com/txs/rename_subaccount', pointer, name).then(function() {
                $scope.wallet.subaccounts[i].name = name;
            });
        } else {
            var d = tx_sender.call('http://greenaddressit.com/addressbook/edit_entry', address, name, 0)
        }
        d.then(function(data) {
            gaEvent('Wallet', 'AddressBookItemRenamed');
            angular.forEach(addressbook.partitions[$routeParams.page-1][2], function(value) {
                if (value.address == address) {
                    value.renaming = false;
                }
            });
        }, function(err) {
            gaEvent('Wallet', 'AddressBookItemRenameFailed', err.args[1]);
            notices.makeNotice('error', 'Error renaming item: ' + err.args[1]);
        });
    };
    $scope.start_rename = function(item) {
        gaEvent('Wallet', 'AddressBookRenameItemStarted');
        item.renaming = true;
        focus('addrbook_rename_' + item.address);
    };
    $scope.save = function() {
        var item = addressbook.new_item;
        if (item.address.indexOf('@') != -1) {
            item.type = 'email';
        }
        tx_sender.call('http://greenaddressit.com/addressbook/add_entry',
                item.address, item.name, 0).then(function(data) {
            if (!data) {
                gaEvent('Wallet', 'AddressBookItemAddFailed', '!data');
                notices.makeNotice('error', 'Error saving item');
                return;
            } else {
                gaEvent('Wallet', 'AddressBookItemAdded');

                addressbook.new_item = undefined;
                notices.makeNotice('success', gettext('New item saved'));
                // go to first page - it should refresh the view:
                $location.path('/address-book/name_'+encodeURIComponent(item.name));
            }
        }, function(err) {
            gaEvent('Wallet', 'AddressBookItemAddFailed', err.args[1]);
            notices.makeNotice('error', gettext('Error saving item: ') + err.args[1]);
        });
    }
    $scope.send_url = function(contact) {
        return '#/send/' + Bitcoin.bs58.encode(
            new Bitcoin.Buffer.Buffer(JSON.stringify(contact), 'utf-8')
        );
    };
}]).controller('SoundController', ['$scope', 'notices', 'wallets', 'gaEvent', function SoundController($scope, notices, wallets, gaEvent) {

    if (!('wallet' in $scope) || !('appearance' in $scope.wallet)) return;
    var soundstate = {sound: false};
    $scope.$watch('wallet.appearance.sound', function(newValue, oldValue) {
        if (newValue === oldValue) return;
        if (!soundstate['sound']) {
            soundstate['sound'] = true;
            if (!('wallet' in $scope) || !('appearance' in $scope.wallet) || !('sound' in $scope.wallet.appearance)) return;
            wallets.updateAppearance($scope, 'sound', newValue).then(function() {
                gaEvent('Wallet', "Sound_"+(newValue?'Enabled':'Disabled'));
                soundstate['sound'] = false;
            }).catch(function(err) {
                gaEvent('Wallet', "Sound_"+(newValue?'Enable':'Disable')+'Failed', err.args[1]);
                notices.makeNotice('error', err.args[1]);
                soundstate['sound'] = false;
            });
        }
    });
}]).controller('AutoLogoutController', ['$scope', 'notices', 'wallets', 'autotimeout', 'gaEvent', function AutoLogoutController($scope, notices, wallets, autotimeout, gaEvent) {

    if (!('appearance' in $scope.wallet)) return;

    $scope.timeoutstate = {timeout: false, altimeout: $scope.wallet.appearance.altimeout};

    autotimeout.registerObserverCallback(function() {
        $scope.mins = Math.floor(autotimeout.left / 1000 / 60);
        $scope.secs = Math.floor((autotimeout.left - ($scope.mins * 60 * 1000)) / 1000);

    });
    $scope.save_logout_timeout = function() {
        if ($scope.timeoutstate['altimeout'] === $scope.wallet.appearance.altimeout) return;
        if (!$scope.timeoutstate['timeout']) {
            $scope.timeoutstate['timeout'] = true;
        }
        wallets.updateAppearance($scope, 'altimeout', $scope.timeoutstate['altimeout']).then(function() {
            gaEvent('Wallet', "Timeoutset");
            //
            $scope.timeoutstate['timeout'] = false;
            $scope.wallet.appearance.altimeout = $scope.timeoutstate['altimeout'];
            autotimeout.start($scope.wallet.appearance.altimeout);

        }).catch(function(err) {
            gaEvent('Wallet', "TimeoutsetFailed");
            notices.makeNotice('error', err.args[1]);
            $scope.timeoutstate['timeout'] = false;
            $scope.altimeout = $scope.wallet.appearance.altimeout;
        });
    };
}]).controller('PgpController', ['$scope', 'notices', 'wallets', function PgpController($scope, notices, wallets) {

    if (!('appearance' in $scope.wallet)) return;

    $scope.pgpstate = {enabled: false, pgp: $scope.wallet.appearance.pgp};

    $scope.save_pgp = function() {
        if ($scope.pgpstate['pgp'] === $scope.wallet.appearance.pgp) return;
        if (!$scope.pgpstate['enabled']) {
            $scope.pgpstate['enabled'] = true;
        }
        wallets.updateAppearance($scope, 'pgp', $scope.pgpstate['pgp']).then(function() {
            $scope.pgpstate['enabled'] = false;
            $scope.wallet.appearance.pgp = $scope.pgpstate['pgp'];

        }).catch(function(err) {
            notices.makeNotice('error', err.args[1]);
            $scope.pgpstate['enabled'] = false;
            $scope.pgp = $scope.wallet.appearance.pgp;
        });
    };
}]).controller('QuickLoginController', ['$scope', 'tx_sender', 'notices', 'wallets', 'gaEvent', 'storage',
        function QuickLoginController($scope, tx_sender, notices, wallets, gaEvent, storage) {
    if (!wallets.requireWallet($scope, true)) return;   // dontredirect=true because one redirect in SettingsController is enough
    if (tx_sender.pin_ident) {
        // logged in via PIN
        $scope.quicklogin = {
            enabled: true,
            device_ident: tx_sender.pin_ident
        };
        $scope.quicklogin.loaded = true;
    } else {
        storage.get(['pin_chaincode', 'pin_ident']).then(function(res) {
            if (res.pin_chaincode == $scope.wallet.hdwallet.chainCode.toString('hex')) {
                // PIN for the same user as currently logged in (via mnemonic)
                $scope.quicklogin = {
                    enabled: true,
                    device_ident: res.pin_ident
                };
            } else {
                $scope.quicklogin = {};
            }
            $scope.quicklogin.loaded = true;
        });
    }

    $scope.$watch('quicklogin.enabled', function(newValue, oldValue) {
        if (newValue === oldValue) return
        if (newValue && !$scope.quicklogin.started_unsetting) {
            if (!$scope.quicklogin.started_setting) {
                $scope.quicklogin.started_setting = true;
                $scope.quicklogin.enabled = false;  // not yet enabled
            } else {
                // finished setting pin
                $scope.quicklogin.started_setting = false;
            }
        } else if (!newValue && !$scope.quicklogin.started_setting) {
            if (!$scope.quicklogin.started_unsetting) {
                $scope.quicklogin.started_unsetting = true;
                $scope.quicklogin.enabled = true;  // not yet disabled
                tx_sender.call('http://greenaddressit.com/pin/remove_pin_login',
                        $scope.quicklogin.device_ident).then(function(data) {
                    gaEvent('Wallet', 'QuickLoginRemoved');
                    delete tx_sender.pin_ident;  // don't try using pin on reconnect
                    $scope.quicklogin.enabled = false;
                    $scope.quicklogin.device_ident = undefined;
                    storage.remove('pin_ident');
                    storage.remove('pin_chaincode');
                    storage.remove('encrypted_seed');
                    notices.makeNotice('success', gettext('PIN removed'));
                }, function(err) {
                    gaEvent('Wallet', 'QuickLoginRemoveFailed', err.args[1]);
                    $scope.quicklogin.started_unsetting = false;
                    notices.makeNotice('error', err.args[1]);
                });
            } else {
                // finished disabling pin
                $scope.quicklogin.started_unsetting = false;
            }
        }
    })
    $scope.set_new_pin = function() {
        if (!$scope.quicklogin.new_pin) return;
        $scope.quicklogin.setting = true;
        var success_message;
        var success = function(device_ident) {
            $scope.quicklogin.setting = false;
            $scope.quicklogin.new_pin = '';
            $scope.quicklogin.enabled = true;
            if (device_ident) {
                $scope.quicklogin.device_ident = device_ident;
            }
            notices.makeNotice('success', success_message);
        }, error = function(err) {
            $scope.quicklogin.setting = false;
            $scope.quicklogin.started_setting = false;
            gaEvent('Wallet', 'PinError', err);
            notices.makeNotice('error', err.args ? err.args[0] : err);
        };
        if ($scope.quicklogin.device_ident) {  // change the existing PIN
            gaEvent('Wallet', 'PinChangeAttempt');
            success_message = gettext('PIN changed');
            tx_sender.change_pin($scope.quicklogin.new_pin).then(success, error);
        } else {  // create a brand new PIN
            gaEvent('Wallet', 'NewPinSetAttempt');
            success_message = gettext('PIN set');
            wallets.create_pin($scope.quicklogin.new_pin, $scope).then(
                success, error);
        }
    };
    $scope.remove_all_pin_logins = function() {
        $scope.quicklogin.started_unsetting = true;
        tx_sender.call('http://greenaddressit.com/pin/remove_all_pin_logins').then(function() {
            gaEvent('Wallet', 'AllPinLoginsRemoved');
            $scope.quicklogin.enabled = false;
            $scope.quicklogin.device_ident = undefined;
            delete tx_sender.pin_ident;  // don't try using pin on reconnect
            storage.remove('pin_ident');
            storage.remove('pin_chaincode');
            storage.remove('encrypted_seed');
            notices.makeNotice('success', gettext('All PINs removed'));
        }, function(err) {
            gaEvent('Wallet', 'AllPinLoginsRemoveFailed', err.args[1]);
            $scope.quicklogin.started_unsetting = false;
            notices.makeNotice('error', err.args[1]);
        });
    }
}]).controller('ThirdPartyController', ['$scope', 'tx_sender', 'notices', 'facebook', 'gaEvent', '$q', 'reddit',
        function($scope, tx_sender, notices, facebook, gaEvent, $q, reddit) {
    $scope.thirdparty = {
        loaded: false,
        fbstate: {},
        redditstate: {},
        customstate: {},
        toggle_fb: function() {
            var that = this;
            if (this.fbstate.enabled) {
                tx_sender.call('http://greenaddressit.com/addressbook/disable_sync', 'facebook').then(function(data) {
                    gaEvent('Wallet', 'FbSyncDisabled');
                    that.toggling_fb = 2;
                    that.fbstate.enabled = false;
                    notices.makeNotice('success', gettext('Facebook integration disabled'));
                }, function(err) {
                    gaEvent('Wallet', 'FbSyncDisableFailed', err.args[1]);
                    that.toggling_fb = false;
                    notices.makeNotice('error', err.args[1]);
                });
            } else {
                gaEvent('Wallet', 'FbSyncEnableAttempt');
                facebook.login(that.fbstate).then(function() {
                    var auth = FB.getAuthResponse();
                    if (that.fbstate.logged_in) {
                        tx_sender.call('http://greenaddressit.com/addressbook/sync_fb', auth.accessToken).then(function() {
                            gaEvent('Wallet', 'FbSyncEnabled');
                            notices.makeNotice('success', gettext('Facebook integration enabled'));
                            that.toggling_fb = 2;
                            that.fbstate.enabled = true;
                        }, function(err) {
                            gaEvent('Wallet', 'FbSyncEnableFailed');
                            notices.makeNotice('error', err.args[1]);
                            that.toggling_fb = false;
                        });
                    } else {
                        that.toggling_fb = false;
                    }
                });
            }
        },
        toggle_reddit: function() {
            var that = this;
            if (this.redditstate.enabled) {
                tx_sender.call('http://greenaddressit.com/addressbook/disable_sync', 'reddit').then(function(data) {
                    gaEvent('Wallet', 'RedditSyncDisabled');
                    that.toggling_reddit = 2;
                    that.redditstate.enabled = false;
                    notices.makeNotice('success', gettext('Reddit integration disabled'));
                }, function(err) {
                    gaEvent('Wallet', 'RedditSyncDisableFailed', err.args[1]);
                    that.toggling_reddit = false;
                    notices.makeNotice('error', err.args[1]);
                });
            } else {
                gaEvent('Wallet', 'RedditSyncEnableAttempt');
                reddit.getToken('identity').then(function(token) {
                    if (token) {
                        tx_sender.call('http://greenaddressit.com/addressbook/sync_reddit', token).then(function() {
                            gaEvent('Wallet', 'RedditSyncEnabled');
                            notices.makeNotice('success', gettext('Reddit integration enabled'));
                            that.toggling_reddit = 2;
                            that.redditstate.enabled = true;
                        }, function(err) {
                            gaEvent('Wallet', 'RedditSyncEnableFailed');
                            notices.makeNotice('error', err.args[1]);
                            that.toggling_reddit = false;
                        });
                    } else {
                        that.toggling_reddit = false;
                    }
                });
            }
        },
        toggle_custom: function() {
            var that = this;
            var change = (that.toggling_custom == 'changing');
            if (this.customstate.enabled && !change) {
                tx_sender.call('http://greenaddressit.com/addressbook/disable_sync', 'custom').then(function(data) {
                    gaEvent('Wallet', 'CustomLoginDisabled');
                    that.customstate.enabled = false;
                    that.customstate.username = that.customstate.password = null;
                    notices.makeNotice('success', gettext('Custom login disabled'));
                }, function(err) {
                    gaEvent('Wallet', 'CustomLoginDisableFailed', err.args[1]);
                    that.toggling_custom = 'initial';
                    notices.makeNotice('error', err.args[1]);
                });
            } else {
                gaEvent('Wallet', 'CustomLoginEnableAttempt');
                tx_sender.call('http://greenaddressit.com/addressbook/sync_custom', that.customstate.username,
                        that.customstate.password).then(function() {
                    gaEvent('Wallet', 'CustomLoginEnabled');
                    if (that.customstate.enabled) {
                        // change=true
                        notices.makeNotice('success', gettext('Custom login changed'));
                        $scope.thirdparty.toggling_custom = false;
                    } else {
                        notices.makeNotice('success', gettext('Custom login enabled'));
                        that.customstate.enabled = true;
                    }
                }, function(err) {
                    gaEvent('Wallet', 'CustomLoginEnableFailed');
                    notices.makeNotice('error', err.args[1]);
                    // go back to 1st step of toggling
                    that.toggling_custom = 'initial';
                });
            }
        }
    };
    tx_sender.call('http://greenaddressit.com/addressbook/get_sync_status').then(function(data) {
        $scope.thirdparty.fbstate.enabled = data.fb;
        $scope.thirdparty.redditstate.enabled = data.reddit;
        $scope.thirdparty.customstate.username = data.username;
        $scope.thirdparty.customstate.enabled = data.username ? true : false;
        $scope.thirdparty.customstate.save_button_label = data.username ? gettext('Change') : gettext('Save');
        $scope.thirdparty.loaded = true;
        $scope.$watch('thirdparty.fbstate.enabled', function(newValue, oldValue) {
            if (newValue === oldValue || $scope.thirdparty.toggling_fb === true) return;
            if ($scope.thirdparty.toggling_fb == 2) {
                $scope.thirdparty.toggling_fb = false;
                return;
            }
            $scope.thirdparty.fbstate.enabled = oldValue;
            $scope.thirdparty.toggling_fb = true;
            $scope.thirdparty.toggle_fb();
        });
        $scope.$watch('thirdparty.redditstate.enabled', function(newValue, oldValue) {
            if (newValue === oldValue || $scope.thirdparty.toggling_reddit === true) return;
            if ($scope.thirdparty.toggling_reddit == 2) {
                $scope.thirdparty.toggling_reddit = false;
                return;
            }
            $scope.thirdparty.redditstate.enabled = oldValue;
            $scope.thirdparty.toggling_reddit = true;
            $scope.thirdparty.toggle_reddit();
        });
        $scope.thirdparty.customstate.save = function() {
            // step 2 - actually enable (disabling the inputs while server processes the request)
            var was_enabled = $scope.thirdparty.customstate.enabled;
            if (was_enabled) {
                $scope.thirdparty.toggling_custom = 'changing';
            } else {
                $scope.thirdparty.toggling_custom = 'enabling';
            }
            $scope.thirdparty.toggle_custom();
        };
        $scope.$watch('thirdparty.customstate.enabled', function(newValue, oldValue) {
            $scope.thirdparty.customstate.save_button_label = newValue ? gettext('Change') : gettext('Save');
            if (newValue === oldValue || $scope.thirdparty.toggling_custom == 'initial') return;
            if ($scope.thirdparty.toggling_custom == 'disabling' && newValue == true) return;
            if ($scope.thirdparty.toggling_custom == 'disabling' || $scope.thirdparty.toggling_custom == 'enabling') {
                $scope.thirdparty.toggling_custom = false;
                return;
            }
            $scope.thirdparty.customstate.enabled = oldValue;
            $scope.thirdparty.customstate.save_button_label = oldValue ? gettext('Change') : gettext('Save');
            if (oldValue) { // disabling
                $scope.thirdparty.toggling_custom = 'disabling';
                $scope.thirdparty.toggle_custom();
                return;
            }
            // step 1 - just show the inputs
            $scope.thirdparty.toggling_custom = 'initial';
        });
    });
}]).controller('TxLimitsController', ['$scope', 'gaEvent', '$modal', 'tx_sender', 'notices', 'wallets',
        function($scope, gaEvent, $modal, tx_sender, notices, wallets) {

    var formatAmountHumanReadable = function(units, is_fiat) {
        // for fiat, to fit the 'satoshi->BTC' conversion, the input value needs to be multiplied by 1M,
        // to get 1 fiat per 100 units
        var mul = {'BTC': 1, 'mBTC': 1000, 'µBTC': 1000000, 'bits': 1000000}[$scope.wallet.unit];
        var cur_mul = is_fiat ? 1000000 : mul;  // already satoshis for BTC
        var satoshi = new Bitcoin.BigInteger(units.toString()).multiply(Bitcoin.BigInteger.valueOf(cur_mul));
        return Bitcoin.Util.formatValue(satoshi.toString());
    };
    var formatAmountInteger = function(amount, is_fiat) {
        // for fiat, 'BTC->satoshi' parsed value needs to be divided by 1M, to get 100 units per 1 fiat
        var div = {'BTC': 1, 'mBTC': 1000, 'µBTC': 1000000, 'bits':1000000}[$scope.wallet.unit];
        var cur_div = is_fiat ? 1000000 : div;
        var satoshi = Bitcoin.Util.parseValue(amount.toString()).divide(Bitcoin.BigInteger.valueOf(cur_div));
        return parseInt(satoshi.toString());
    }

    var modal;

    $scope.change_tx_limits = function() {
        gaEvent('Wallet', 'ChangeTxLimitsModal');
        $scope.limits_editor = {
            currency: $scope.wallet.limits.is_fiat ? 'fiat' : 'BTC',
            single_tx: formatAmountHumanReadable($scope.wallet.limits.per_tx, $scope.wallet.limits.is_fiat),
            total: formatAmountHumanReadable($scope.wallet.limits.total, $scope.wallet.limits.is_fiat)
        };
        modal = $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_tx_limits.html',
            scope: $scope
        });
    };

    $scope.save_limits = function() {
        var is_fiat = $scope.limits_editor.currency == 'fiat';
        var data = {
            is_fiat: is_fiat,
            per_tx: formatAmountInteger($scope.limits_editor.single_tx, is_fiat),
            total: formatAmountInteger($scope.limits_editor.total, is_fiat)
        };
        if (data.is_fiat != $scope.wallet.limits.is_fiat ||
                data.per_tx > $scope.wallet.limits.per_tx ||
                data.total > $scope.wallet.limits.total) {
            var do_change = function() {
                return wallets.get_two_factor_code($scope, 'change_tx_limits', data).then(function(twofac_data) {
                    return tx_sender.call('http://greenaddressit.com/login/change_settings', 'tx_limits', data, twofac_data);
                });
            }
        } else {
            var do_change = function() {
                return tx_sender.call('http://greenaddressit.com/login/change_settings', 'tx_limits', data);
            }
        }
        $scope.limits_editor.saving = true;
        do_change().then(function() {
            $scope.wallet.limits = data;
            notices.makeNotice('success', gettext('Limits updated successfully'));
            modal.close();
        }, function(err) {
            notices.makeNotice('error', err.args[1]);
        }).finally(function() { $scope.limits_editor.saving = false; });
    };
}]).controller('SubwalletsController', ['$scope', 'tx_sender', '$q', 'notices', '$location', '$modal', '$rootScope', 'mnemonics', 'branches',
        function($scope, tx_sender, $q, notices, $location, $modal, $rootScope, mnemonics, branches) {
    var subwallets = $scope.subwallets = {
        existing: $scope.wallet.subaccounts,
        _get_min_unused_pointer: function() {
            var min_unused_pointer = null, pointers = [];
            for (var i = 0; i < this.existing.length; i++) {
                pointers.push(this.existing[i].pointer);
            }
            pointers.sort(function(a,b) { return a-b; });
            for (var i = 1; i < pointers.length; i++) {
                if (pointers[i] > pointers[i-1] + 1) {
                    min_unused_pointer = pointers[i-1] + 1;
                }
            }
            if (min_unused_pointer === null) {
                if (pointers.length) {
                    min_unused_pointer = pointers[pointers.length-1] + 1;
                } else {
                    min_unused_pointer = 1;
                }
            }
            return min_unused_pointer;
        },
        _derive_hd: function(pointer, hdwallet) {
            var hdwallet_ = hdwallet || $scope.wallet.hdwallet;
            return $q.when(hdwallet_.deriveHardened(3)).then(function(k) {
                return $q.when(k.deriveHardened(pointer)).then(function(k) {
                    return {
                        pub: k.keyPair.getPublicKeyBuffer().toString('hex'),
                        chaincode: k.chainCode.toString('hex')
                    };
                });
            });
        },
        _derive_btchip: function(pointer) {
            return $scope.wallet.btchip.app.getWalletPublicKey_async("3'/"+pointer+"'").then(function(result) {
                var pub = new Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(
                    new Bitcoin.Buffer.Buffer(result.publicKey.toString(HEX), 'hex')
                );
                pub.compressed = true;
                return {
                    pub: pub.getPublicKeyBuffer.toString('hex'),
                    chaincode: result.chainCode.toString(HEX)
                };
            });
        },
        _derive_trezor: function(pointer) {
            return $scope.wallet.trezor_dev.getPublicKey([3 + 0x80000000, pointer + 0x80000000]).then(function(result) {
                var cc = result.message.node.chain_code, pk = result.message.node.public_key;
                cc = cc.toHex ? cc.toHex() : cc;
                pk = pk.toHex ? pk.toHex() : pk;
                return {
                    pub: pk,
                    chaincode: cc
                };
            })
        },
        create_new_2of3: function() {
            var that = this, min_unused_pointer = null, pointers = [];
            that.adding_subwallet = true;
            that.generating_2of3_seed = true;

            var max256int_hex = '', mnemonic;
            while (max256int_hex.length < 256/4) max256int_hex += 'F';
            var TWOPOWER256 = new Bitcoin.BigInteger(max256int_hex, 16).add(Bitcoin.BigInteger.ONE);
            if (that.new_2of3_xpub) {
                var hdwallet_2of3_d = $q.when(Bitcoin.HDWallet.fromBase58(that.new_2of3_xpub));
            } else {
                entropy = Bitcoin.ecdsa.getBigRandom(TWOPOWER256).toByteArrayUnsigned();
                while (entropy.length < 32) entropy.unshift(0);
                var hdwallet_2of3_d = mnemonics.toMnemonic(entropy).then(function(mnemonic_) {
                    mnemonic = mnemonic_;
                    return mnemonics.toSeed(mnemonic).then(function (seed) {
                        return $q.when(Bitcoin.HDWallet.fromSeedHex(seed, cur_net));
                    }, null, function(progress) {
                        that.seed_progress_2of3 = Math.round(progress);
                    });
                });
            }
            var derive_xpub = function(subaccount) {
                var xpub = new Bitcoin.bitcoin.HDNode(
                    Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(
                        new Bitcoin.Buffer.Buffer(deposit_pubkey, 'hex'),
                        cur_net
                    ),
                    new Bitcoin.Buffer.Buffer(deposit_chaincode, 'hex')
                );
                return $q.when(xpub.derive(branches.SUBACCOUNT)).then(function(xpub) {
                    return $q.when(xpub.subpath($scope.wallet.gait_path)).then(function(xpub) {
                        return $q.when(xpub.derive(subaccount)).then(function(xpub) {
                            return xpub.toBase58();
                        });
                    });
                });
            };
            hdwallet_2of3_d.then(function(hdwallet) {
                that.generating_2of3_seed = false;

                var min_unused_pointer = that._get_min_unused_pointer();
                if ($scope.wallet.hdwallet.keyPair.d) var derive_fun = that._derive_hd;
                else if ($scope.wallet.trezor_dev) var derive_fun = that._derive_trezor;
                else var derive_fun = that._derive_btchip;
                return derive_xpub(min_unused_pointer).then(function(ga_xpub) {
                    var scope = angular.extend($scope.$new(), {
                        mnemonic_2of3: mnemonic,
                        xpub_2of3: hdwallet.toBase58(false),
                        xpub_ga_2of3: ga_xpub
                    });
                    return derive_fun(min_unused_pointer).then(function(hdhex) {
                        if (that.new_2of3_xpub) {
                            // we can't priv-derive 3'/subaccount' from a public key
                            var hdhex_recovery_d = $q.when({
                                pub: Bitcoin.bs58check.decode(hdwallet.keyPair.toWIF()).toString('hex'),
                                chaincode: hdwallet.chainCode.toString('hex')
                            });
                        } else {
                            var hdhex_recovery_d = that._derive_hd(min_unused_pointer, hdwallet)
                        }
                        return hdhex_recovery_d.then(function(hdhex_recovery) {
                            return tx_sender.call('http://greenaddressit.com/txs/create_subaccount',
                                min_unused_pointer,
                                that.new_2of3_label,
                                hdhex.pub,
                                hdhex.chaincode,
                                hdhex_recovery.pub,
                                hdhex_recovery.chaincode
                            ).then(function(receiving_id) {
                                $modal.open({
                                    templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_mnemonic.html',
                                    scope: scope
                                });
                                subaccount = {type: '2of3', name: that.new_2of3_label,
                                    pointer: min_unused_pointer, receiving_id: receiving_id};
                                subaccount['2of3_backup_chaincode'] = hdhex_recovery.chaincode;
                                subaccount['2of3_backup_pubkey'] = hdhex_recovery.pub;
                                that.existing.push(subaccount);
                                that.new_2of3_label = '';
                                that.new_2of3_xpub = '';
                            });
                        });
                    });
                });
            }).catch(function(e) {
                notices.makeNotice('error', e.args[1] || e);
            }).finally(function() {
                that.generating_2of3_seed = that.adding_subwallet = false;
            });;
        },
        create_new: function() {
            var that = this, min_unused_pointer = this._get_min_unused_pointer();
            that.adding_subwallet = true;
            if ($scope.wallet.hdwallet.keyPair.d) var derive_fun = that._derive_hd;
            else if ($scope.wallet.trezor_dev) var derive_fun = that._derive_trezor;
            else var derive_fun = that._derive_btchip;
            derive_fun(min_unused_pointer).then(function(hdhex) {
                return tx_sender.call('http://greenaddressit.com/txs/create_subaccount',
                    min_unused_pointer,
                    that.new_label,
                    hdhex.pub,
                    hdhex.chaincode
                ).then(function(receiving_id) {
                    that.existing.push({type: 'simple', name: that.new_label,
                        pointer: min_unused_pointer, receiving_id: receiving_id})
                    that.new_label = '';
                    $rootScope.safeApply(function() { that.adding_subwallet = false; });
                });
            }).catch(function(e) {
                notices.makeNotice('error', e.args[1] || e);
                $rootScope.safeApply(function() { that.adding_subwallet = false; });
            });
        },
        start_rename: function(subaccount) {
            subaccount.new_name = subaccount.name;
            subaccount.renaming = true;
        },
        rename: function(subaccount) {
            if (subaccount.new_name == subaccount.name) {
                // nothing to do
                subaccount.renaming = false;
            } else {
                tx_sender.call('http://greenaddressit.com/txs/rename_subaccount',
                        subaccount.pointer, subaccount.new_name).then(function() {
                    subaccount.name = subaccount.new_name;
                    subaccount.renaming = false;
                    notices.makeNotice('success', gettext('Renamed successfully'));
                }, function(err) {
                    notices.makeNotice('error', err.args[1]);
                });
            }
        },
        send_from: function(subaccount) {
            $scope.wallet.current_subaccount = subaccount.pointer;
            $location.path('/send');
        },
        receive_to: function(subaccount) {
            $scope.wallet.current_subaccount = subaccount.pointer;
            $location.path('/receive');
        }
    };
}]).controller('TouchIdController', ['$scope', 'tx_sender', 'wallets', 'notices', 'storage',
        function($scope, tx_sender, wallets, notices, storage) {
    var touchId = $scope.touchId = {
        isAvailable: false,
        enabled: false
    };
    storage.get('pin_ident_touchid').then(function(devid) {
        if (devid) {
            touchId.enabled = true;
        }
    });
    $scope.$watch('touchId.enabled', function(newValue, oldValue) {
        if (newValue === oldValue) return
        if (newValue && !$scope.touchId.started_unsetting) {
            if (!$scope.touchId.started_setting) {
                $scope.touchId.started_setting = true;
                $scope.touchId.enabled = false;  // not yet enabled
                var randomHex = Bitcoin.randombytes(8).toString('hex').slice(0, 15);
                cordova.exec(function(param) {
                    $scope.$apply(function(touchid_ident) {
                        $scope.touchId.enabled = true;
                        wallets.create_pin(randomHex, $scope, '_touchid')
                    });
                }, function(fail) {
                    console.log('CDVTouchId.setSecret failed: ' + fail)
                }, "CDVTouchId", "setSecret", [randomHex]);
            } else {
                // finished setting pin
                $scope.touchId.started_setting = false;
            }
        } else if (!newValue && !$scope.touchId.started_setting) {
            if (!$scope.touchId.started_unsetting) {
                $scope.touchId.started_unsetting = true;
                $scope.touchId.enabled = true;  // not yet disabled
                return storage.get('pin_ident_touchid').then(function(devid) {
                    tx_sender.call('http://greenaddressit.com/pin/remove_pin_login',
                        devid).then(function(data) {
                        cordova.exec(function(param) {
                            $scope.$apply(function() {
                                storage.remove('pin_ident_touchid')
                                storage.remove('encrypted_seed_touchid')
                                $scope.touchId.enabled = false;
                            });
                        }, function(fail) {
                            console.log('CDVTouchId.removeSecret failed: ' + fail)
                        }, "CDVTouchId", "removeSecret", []);
                    });
                });
            } else {
                // finished disabling pin
                $scope.touchId.started_unsetting = false;
            }
        }
    });
    if (window.cordova && cordova.platformId == 'ios') {
        document.addEventListener('deviceready', function () {
            cordova.exec(function(param) {
                $scope.$apply(function() {
                    touchId.isAvailable = param;
                });
            }, function(fail) {
                console.log('CDVTouchId.isAvailable failed: ' + fail)
            }, "CDVTouchId", "isAvailable", []);
        });
    }
}]);
