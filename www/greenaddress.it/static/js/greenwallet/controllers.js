angular.module('greenWalletControllers', [])
.controller('WalletController', ['$scope', 'tx_sender', '$modal', 'notices', 'gaEvent', '$location', 'wallets', '$http', '$q', 'parse_bitcoin_uri', 'parseKeyValue', 'backButtonHandler', '$modalStack',
        function WalletController($scope, tx_sender, $modal, notices, gaEvent, $location, wallets, $http, $q, parse_bitcoin_uri, parseKeyValue, backButtonHandler, $modalStack) {
    // appcache:
    applicationCache.addEventListener('updateready', function() {
        $scope.$apply(function() {
            $scope.update_available = true;
        });
    });

    $scope.cordova_platform = window.cordova && cordova.platformId;
    
    $scope.update_now = function() {
        wallets.askForLogout($scope, gettext('You need to log out to update cache.')).then(function() {
            window.applicationCache.swapCache();
            window.location.reload();
        });
    };
    $scope.logout = function() {
        wallets.askForLogout($scope).then(function() {
            clearwallet();
            tx_sender.logout();
            $location.path('/');
            $scope.is_loading = 0;  // seems is_loading > 0 while logging out breaks login (ng-disabled checkbox)
        });
    };
    var updating = true, updating_txs = false;
    if (window.WalletControllerInitVars) {
        // keep a copy for signup controller in case user goes back
        window.GlobalWalletControllerInitVars = window.WalletControllerInitVars;
    }
    $scope.clearWalletInitVars = function() {
        $scope.wallet.send_to_receiving_id_bitcoin_uri = undefined;
        window.WalletControllerInitVars = undefined;
    }
    $scope.processWalletVars = function() {
        var destPath = $location.path(), destAmount = $location.search().amount, destUri = $location.search().uri,
            variables = {};
        if ($location.search().redir) {
            destPath = $location.search().redir;
            if (destPath.indexOf('?') != -1) {
                variables = parseKeyValue(destPath.split('?')[1]);
                destPath = destPath.split('?')[0];
            }
            destAmount = destAmount || variables.amount;
            destUri = destUri || variables.uri;
        }
        if (destPath.indexOf('/redeem/') == 0) {
            if (!window.WalletControllerInitVars) window.WalletControllerInitVars = {};
            var redeem_key = window.WalletControllerInitVars.redeem_key = destPath.slice(8).replace(/\//g, '');
            window.WalletControllerInitVars.redeem_closed = false;
            if (destAmount) {
                // can be also provided already by URL before #hash (useful for facebook opengraph data)
                window.WalletControllerInitVars.redeem_amount = destAmount;
            }
            var is_bip38 = window.WalletControllerInitVars.redeem_is_bip38 = Bitcoin.BIP38.isBIP38Format(redeem_key);
            var type = is_bip38 ? 'hash' : 'pubkey';
            if (type == 'hash') {
                var hash_or_pubkey = Bitcoin.convert.wordArrayToBytes(Bitcoin.Util.sha256ripe160(redeem_key));
            } else {
                var hash_or_pubkey = new Bitcoin.ECKey(redeem_key).getPub().toBytes();
            }
            tx_sender.call('http://greenaddressit.com/txs/get_redeem_message', type, hash_or_pubkey).then(function(message) {
                $scope.wallet.redeem_message = message;
            });
        }
        if (destPath.indexOf('/pay/') == 0) {
            window.WalletControllerInitVars = {
                send_to_receiving_id: destPath.slice(5).replace(/\//g, ''),
                send_to_receiving_id_amount: destAmount,
                send_from: Object.keys(variables).length ? variables.from : $location.search().from,
                send_unencrypted: Object.keys(variables).length ? variables.unencrypted : $location.search().unencrypted
            };
        }
        if (destPath.indexOf('/uri/') == 0) {
            var parsed_uri = parse_bitcoin_uri(destUri);
            var initVars = window.WalletControllerInitVars = {
                send_to_receiving_id_bitcoin_uri: destUri
            };    
            initVars.send_to_receiving_id = parsed_uri.recipient;
            initVars.send_to_receiving_id_amount = Bitcoin.Util.parseValue(parsed_uri.amount).toString();
        }

        if (window.WalletControllerInitVars) {
            angular.extend($scope.wallet, WalletControllerInitVars);
        }

        if ($scope.wallet.send_to_receiving_id_bitcoin_uri) {
            $scope.wallet.signuplogin_header = BASE_URL + '/' + LANG + '/wallet/partials/signuplogin/header_pay.html'
            var parsed = parse_bitcoin_uri($scope.wallet.send_to_receiving_id_bitcoin_uri);
            if (parsed.r) {
                $scope.wallet.send_to_receiving_id = undefined;  // ignore address from the URI if 'r' is present
                $scope.payreq_loading = true;
                $scope.has_payreq = true;
                return tx_sender.call('http://greenaddressit.com/vault/process_bip0070_url', parsed.r).then(function(data) {
                    $scope.payreq_loading = false; 
                    var amount = 0;
                    for (var i = 0; i < data.outputs.length; i++) {
                        var output = data.outputs[i];
                        amount += output.amount;
                    }
                    $scope.wallet.send_to_receiving_id_amount = amount;
                    $scope.wallet.send_to_verified_common_name = data.merchant_cn;
                    data.request_url = parsed.r;
                    $scope.wallet.send_to_payment_request = data;
                }).catch(function(err) {
                    notices.makeNotice('error', gettext('Failed processing payment protocol request:') + ' ' + err.desc);
                });
            }
        } else if ($scope.wallet.send_to_receiving_id) {
            $scope.wallet.signuplogin_header = BASE_URL + '/' + LANG + '/wallet/partials/signuplogin/header_pay.html'
        } else if ($scope.wallet.redeem_key) {
            $scope.wallet.signuplogin_header = BASE_URL + '/' + LANG + '/wallet/partials/signuplogin/header_redeem.html'
        }

        return $q.when();
    }
    
    var clearwallet = function() {
        $scope.wallet = {
            show_fiat: false,
            toggle_balance_title: function() {
                this.show_fiat = !this.show_fiat;
            },
            update_balance: function(first) {
                var that = this;
                tx_sender.call('http://greenaddressit.com/txs/get_balance').then(function(data) {
                    that.final_balance = data.satoshi;
                    that.fiat_currency = data.fiat_currency;
                    that.fiat_value = data.fiat_value;
                    that.fiat_rate = data.fiat_exchange;
                    if (first) {
                        $scope.$broadcast('first_balance_updated');
                    }
                }).finally(function() { updating = false; });
            },
            refresh_transactions: function(notifydata) {
                if (updating_txs) return;
                updating_txs = true;
                wallets.getTransactions($scope, notifydata).then(function(data) {
                    $scope.wallet.transactions = data;
                }).finally(function() { updating_txs = false; });
            },
            clear: clearwallet,
            get_tx_output_value: function(txhash, i, no_electrum) {
                if (!no_electrum && tx_sender.electrum) {
                    var d = $q.defer();
                    return tx_sender.electrum.issueTransactionGet(txhash).then(function(rawtx) {
                        var value = Bitcoin.Transaction.deserialize(rawtx).outs[i].value;
                        return new Bitcoin.BigInteger(value.toString());
                    }, function(err) {
                        return $q.reject(err);
                    });
                    return d.promise;
                } else {
                    var is_chrome_app = window.chrome && chrome.storage;
                    // don't allow transactions in Chrome app or Cordova when no Electrum is available
                    if (!no_electrum && (window.cordova || is_chrome_app)) return $q.reject(gettext('Electrum setup failed'));
                    return $q.when($scope.wallet.transactions.output_values[[txhash, i]]);
                }
            },
            send_to_receiving_id: (window.WalletControllerInitVars && WalletControllerInitVars.send_to_receiving_id) ||
                                  window.location.href.indexOf(LANG+'/pay/') != -1 ||
                                  window.location.href.indexOf(LANG+'/uri/?uri=bitcoin') != -1,
            signuplogin_header: BASE_URL + '/' + LANG + '/wallet/partials/signuplogin/header_wallet.html'
        };
    };
    clearwallet();
    $scope.$on('block', function(event, data) {
        if (!$scope.wallet.transactions || !$scope.wallet.transactions.list.length) return;
        $scope.$apply(function() {
            for (var i = 0; i < $scope.wallet.transactions.list.length; i++) {
                if (!$scope.wallet.transactions.list[i].block_height) {
                    // if any unconfirmed, refetch all txs to get the block height
                    $scope.wallet.refresh_transactions();
                    break;
                }
                $scope.wallet.transactions.list[i].confirmations = data.count - $scope.wallet.transactions.list[i].block_height + 1;
            }
        });
    });
    $scope.processWalletVars();
    $scope.$on('login', function() {
        $scope.wallet.update_balance(true);
        $scope.wallet.refresh_transactions();
        $scope.$on('transaction', function(event, data) {
            if (updating) return;
            updating = true;
            $scope.wallet.update_balance();
            $scope.wallet.refresh_transactions(data);
        });
        if ($scope.wallet.expired_deposits && $scope.wallet.expired_deposits.length) {
            $scope.redeposit_modal = $modal.open({
                templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_redeposit.html',
                controller: 'RedepositController',
                scope: $scope
            });
        }
        wallets.getTwoFacConfig($scope);  // required for 2FA missing warning
    });

    if ($scope.wallet.send_to_receiving_id) {
        $scope.show_bitcoin_uri = function(show_qr) {
            if ($scope.bitcoin_uri) {
                if (show_qr) $scope.show_url_qr($scope.bitcoin_uri);
            } else {
                gaEvent('ReceivePage', 'ShowBitcoinUri');
                $scope.generating_bitcoin_uri = true;
                tx_sender.call('http://greenaddressit.com/vault/fund_receiving_id',
                               $scope.wallet.send_to_receiving_id).then(function(p2sh) {
                    $scope.bitcoin_uri = 'bitcoin:' + p2sh;
                    if ($scope.wallet.send_to_receiving_id_amount) {
                        $scope.bitcoin_uri += '?amount=' + Bitcoin.Util.formatValue($scope.wallet.send_to_receiving_id_amount);
                    }
                    if (show_qr) $scope.show_url_qr($scope.bitcoin_uri);
                }, function(err) {
                    notices.makeNotice('error', err.desc);
                }).finally(function() { $scope.generating_bitcoin_uri = false; });
            }
        };
    }

    $scope.show_url_qr = function(url) {
        gaEvent('Wallet', 'ShowUrlQRModal');
        $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_url_qr.html',
            controller: 'UrlQRController',
            resolve: {url: function() { return url; }}
        });
    };

    $scope.verify_mnemonic = function() {
        gaEvent('Wallet', 'VerifyMnemonicModal');
        var indices = $scope.verify_mnemonics_words_indices = [];
        $scope.verified_mnemonic_words = ['', '', '', ''];
        $scope.verified_mnemonic_errors = ['', '', '', ''];
        for (var i = 0; i < 4; i++) {
            indices.push(Math.floor(Math.random() * 24) + 1);
            while (indices.indexOf(indices[indices.length - 1]) < indices.length - 1) {
                indices[indices.length - 1] = Math.floor(Math.random() * 24) + 1;
            }
        }
        indices.sort(function(a, b) { return a - b; });
        $scope.verify_mnemonic_submit = function() {
            var valid = true;
            var valid_words = $scope.wallet.mnemonic.split(' ');
            for (var i = 0; i < 4; i++) {
                if (!$scope.verified_mnemonic_words[i]) {
                    $scope.verified_mnemonic_errors[i] = gettext('Please provide this word');
                    valid = false;
                } else if ($scope.verified_mnemonic_words[i] != valid_words[indices[i]-1]) {
                    $scope.verified_mnemonic_errors[i] = gettext('Incorrect word');
                    valid = false;
                } else {
                    $scope.verified_mnemonic_errors[i] = '';
                }
            }

            if (valid) {
                modal.close();
                wallets.updateAppearance($scope, 'mnemonic_verified', 'true').catch(function(e) {
                    notices.makeNotice('error', e);
                })
            }
        }
        var modal = $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_verify_mnemonic.html',
            scope: $scope
        });
    }

    $scope.$watch(function() { return $location.path(); }, function(newValue, oldValue) {
        $modalStack.dismissAll();
        if (newValue == '/') tx_sender.logout();  // logout on navigation to login page
        var pathname = window.location.pathname
        // don't include addresses:
        if (newValue.indexOf('/send/') == 0) newValue = '/send/_ad_';
        if (pathname.indexOf('/'+LANG+'/pay/') == 0) pathname = BASE_URL+'/'+LANG+'/pay/_ad_';
        if (pathname.indexOf('/'+LANG+'/redeem/') == 0) pathname = BASE_URL+'/'+LANG+'/redeem/_enckey_';
        pathname = pathname + '#' + newValue;
        if ($scope.wallet.signup && !$scope.wallet.signup_info_replaced && pathname.indexOf('wallet/#/info') != -1) {
            $scope.wallet.signup_info_replaced = true;
            pathname = pathname.replace('wallet/#/info', 'wallet/#/info_from_signup');
        }
        try {
            _gaq.push(['set', 'page', pathname]);
        } catch(e) {}
        setTimeout(function() { gaEvent('_pageview', pathname); }, 1000);
    });

}]).controller('UrlQRController', ['$scope', 'url', function UrlQRController($scope, url) {
    $scope.url = url;
}]).controller('RedepositController', ['$scope', 'tx_sender', 'wallets', 'notices', '$q',
        function RedepositController($scope, tx_sender, wallets, notices, $q) {
    $scope.redeposit_estimated_fees = {
        single_tx: 10000 * Math.ceil((300+$scope.wallet.expired_deposits.length*180)/1000),
        multiple_tx: 10000 * $scope.wallet.expired_deposits.length
    }
    var redeposit = function(txos, twofac_data) {
        var deferred = $q.defer();
        var txos_in = [];
        for (var i = 0; i < txos.length; ++i) {
            txos_in.push([txos[i].txhash, txos[i].out_n]);
        }
        tx_sender.call("http://greenaddressit.com/vault/prepare_redeposit", txos_in).then(function(data) {
            if (twofac_data) {
                var scope = undefined;
            } else {
                var scope = $scope;  // it asks for two fac if scope is provided
            }
            wallets.sign_and_send_tx(scope, data, false, twofac_data).then(function() {
                deferred.resolve();
            }, function(err) {
                deferred.reject(err);
            });
        }, function(error) {
            deferred.reject(error.desc);
        });
        return deferred.promise;
    };
    $scope.redeposit_single_tx = function() {
        $scope.redepositing = true;
        redeposit($scope.wallet.expired_deposits).then(function() {
            $scope.redeposit_modal.close();
            notices.makeNotice('success', gettext('Re-depositing successful!'));
        }, function(err) {
            $scope.redepositing = false;
            notices.makeNotice('error', err);
        });
    };
    $scope.redeposit_multiple_tx = function() {
        $scope.redepositing = true;
        return tx_sender.call("http://greenaddressit.com/vault/prepare_redeposit",
                [[$scope.wallet.expired_deposits[0].txhash, $scope.wallet.expired_deposits[0].out_n]]).then(function() {
            // prepare one to set appropriate tx data for 2FA
            return wallets.get_two_factor_code($scope, 'send_tx').then(function(twofac_data) {
                var promise = $q.when();
                for (var i = 0; i < $scope.wallet.expired_deposits.length; ++i) {
                    (function(i) { promise = promise.then(function() {
                        return redeposit([$scope.wallet.expired_deposits[i]], twofac_data);
                    }, function(err) {
                        return $q.reject(err);
                    });})(i);
                }
                promise.then(function() {
                    $scope.redeposit_modal.close();
                    notices.makeNotice('success', gettext('Re-depositing successful!'));
                }, function(error) {
                    $scope.redepositing = false;
                    notices.makeNotice('error', error);
                });
                return promise;
            });
        }, function(error) {
            $scope.redepositing = false;
            notices.makeNotice('error', error);
        })
        
    };
}]);
