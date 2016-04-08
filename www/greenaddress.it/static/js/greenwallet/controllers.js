angular.module('greenWalletControllers', [])
.controller('WalletController', ['$scope', 'tx_sender', '$uibModal', 'notices', 'gaEvent', '$location', 'wallets', '$http', '$q', 'parse_bitcoin_uri', 'parseKeyValue', 'backButtonHandler', '$uibModalStack', 'sound', 'blind', 'storage',
        function WalletController($scope, tx_sender, $uibModal, notices, gaEvent, $location, wallets, $http, $q, parse_bitcoin_uri, parseKeyValue, backButtonHandler, $uibModalStack, sound, blind, storage) {
    // appcache:
    applicationCache.addEventListener('updateready', function() {
        $scope.$apply(function() {
            $scope.update_available = true;
        });
    });

    $scope.cordova_platform = window.cordova && cordova.platformId;

    var exchanges = $scope.exchanges = {
        BITSTAMP: 'Bitstamp',
        LOCALBTC: 'LocalBitcoins',
        BTCAVG: 'BitcoinAverage',
        TRT: 'The Rock Trading',
        BITFINEX: 'BitFinex',
        BTCE: 'BTC-e',
        HUOBI: 'Huobi',
        BTCCHINA: 'BTCChina',
        KRAKEN: 'Kraken',
        QUADRIGACX: 'QuadrigaCX'
    };

    if (window.chrome && chrome.runtime && chrome.runtime.getManifest) {
        var app_version = chrome.runtime.getManifest().version;
    } else if ($scope.cordova_platform) {
        var app_version;
        document.addEventListener('deviceready', function () {
            cordova.getAppVersion.getVersionNumber().then(function (version) {
                app_version = version;
                $scope.$apply(function() {
                    $scope.wallet.version = app_version;
                });
            });
        });
    } else {
        var app_version = null
    }

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
            var is_bip38 = window.WalletControllerInitVars.redeem_is_bip38 = new Bitcoin.bip38().verify(redeem_key);
            var type = is_bip38 ? 'hash' : 'pubkey';
            if (type == 'hash') {
                var hash_or_pubkey = Bitcoin.bitcoin.crypto.hash160(redeem_key);
            } else {
                var hash_or_pubkey = Bitcoin.bitcoin.ECPair.fromWIF(redeem_key).getPublicKeyBuffer();
            }
            tx_sender.call('http://greenaddressit.com/txs/get_redeem_message',
                    type, Array.from(hash_or_pubkey)).then(function(message) {
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
                    notices.makeNotice('error', gettext('Failed processing payment protocol request:') + ' ' + err.args[1]);
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
            balanceLoaded: false,
            version: app_version,
            update_balance: function(first) {
                var that = this;
                that.balance_updating = true;
                if (!cur_net.isAlpha) {
                    tx_sender.call('http://greenaddressit.com/txs/get_balance', $scope.wallet.current_subaccount)
                        .then(function(data) {
                            that.final_balance = data.satoshi;
                            that.fiat_currency = data.fiat_currency;
                            that.fiat_value = data.fiat_value;
                            that.fiat_rate = data.fiat_exchange;
                            // copy in .fiat to allow passing to format_fiat filter
                            // without running the digest cycle too often
                            // (having an object here instead of JSON representation
                            //  causes calling format_fiat repeatedly)
                            that.fiat = JSON.stringify({rate: data.fiat_exchange,
                                                        currency: data.fiat_currency});
                            that.fiat_last_fetch = 1*((new Date).getTime()/1000).toFixed();
                            that.fiat_exchange_extended = exchanges[$scope.wallet.fiat_exchange];
                            if (first) {
                                $scope.$broadcast('first_balance_updated');
                            }
                        })
                        .finally(function() {
                            updating = that.balance_updating = false;
                        });
                } else {
                    $scope.wallet.utxo = {};
                    var final_balances = {};
                    for (var i = 0; i < $scope.wallet.subaccounts.length; ++i) {
                        var subaccount = $scope.wallet.subaccounts[i];
                        $scope.wallet.utxo[subaccount.pointer] = [];
                        final_balances[subaccount.pointer] = 0;
                    }
                    tx_sender.call(
                        'http://greenaddressit.com/txs/get_all_unspent_outputs',
                        0   // include zero-confs
                    ).then(function(utxos) {
                        var rawtx_ds = [];
                        for (var i = 0; i < utxos.length; ++i) {
                            (function(utxo) {
                                rawtx_ds.push(tx_sender.call(
                                    'http://greenaddressit.com/txs/get_raw_unspent_output',
                                    utxo.txhash, utxo.asset_id
                                ).then(function(rawtx) {
                                    return {
                                        txhash: utxo.txhash,
                                        rawtx: rawtx,
                                        pt_idx: utxo.pt_idx,
                                        pointer: utxo.pointer,
                                        subaccount: utxo.subaccount
                                    };
                                }));
                            })(utxos[i]);
                        }
                        return $q.all(rawtx_ds);
                    }).then(function(rawtxs) {
                        var unblind_ds = [];
                        for (var i = 0; i < rawtxs.length; ++i) {
                            (function(rawtx) {
                                var tx = Bitcoin.contrib.transactionFromHex(
                                    rawtx.rawtx
                                );
                                var key =
                                    'unblinded_value_' + rawtx.txhash + ':' +
                                    rawtx.pt_idx;
                                unblind_ds.push(storage.get(key).then(
                                        function(value) {
                                    if (value !== null) {
                                        return {value: value};
                                    }
                                    return blind.unblindOutValue(
                                        $scope, tx.outs[rawtx.pt_idx],
                                        rawtx.subaccount, rawtx.pointer
                                    )
                                }).then(function(data) {
                                    storage.set(key, data.value);
                                    final_balances[rawtx.subaccount] += +data.value;
                                    $scope.wallet.utxo[rawtx.subaccount].push({
                                        txhash: rawtx.txhash,
                                        data: {
                                            pubkey_pointer: rawtx.pointer,
                                            pt_idx: rawtx.pt_idx,
                                            value: data.value
                                        },
                                        out: tx.outs[rawtx.pt_idx]
                                    })
                                }, function(e) {
                                    // ignore invalid transactions
                                    if (e !== "Invalid transaction.") {
                                        throw e;
                                    }
                                }));
                            })(rawtxs[i]);
                        }
                        return $q.all(unblind_ds);
                    }).then(function() {
                        return tx_sender.call('http://greenaddressit.com/txs/get_balance', $scope.wallet.current_subaccount).then(function(data) {
                            that.final_balance = final_balances[$scope.wallet.current_subaccount];
                            that.fiat_currency = data.fiat_currency;
                            that.fiat_value = data.fiat_value;
                            that.fiat_rate = data.fiat_exchange;
                            // copy in .fiat to allow passing to format_fiat filter
                            // without running the digest cycle too often
                            // (having an object here instead of JSON representation
                            //  causes calling format_fiat repeatedly)
                            that.fiat = JSON.stringify({rate: data.fiat_exchange,
                                                        currency: data.fiat_currency});

                            that.fiat_last_fetch = 1*((new Date).getTime()/1000).toFixed();
                            that.fiat_exchange_extended = exchanges[$scope.wallet.fiat_exchange];
                            if (first) {
                                $scope.$broadcast('first_balance_updated');
                            }
                        });
                    }).finally(function() { updating = that.balance_updating = false; });
                }
            },
            clear: clearwallet,
            get_tx_output_value: function(txhash, i, no_electrum) {
                if (!no_electrum && tx_sender.electrum) {
                    var d = $q.defer();
                    return tx_sender.electrum.issueTransactionGet(txhash).then(function(rawtx) {
                        if (!rawtx) { return $q.reject('no electrum'); }
                        var value = Bitcoin.Transaction.deserialize(rawtx).outs[i].value;
                        return new Bitcoin.BigInteger(value.toString());
                    }, function(err) {
                        return $q.reject(err == 'timeout' ? 'no electrum' : err);
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
    $scope.$watch('wallet.current_subaccount', function(newValue, oldValue) {
        if (newValue !== oldValue && newValue !== undefined) {
            wallets.updateAppearance($scope, "current_subaccount", newValue);
        }
    });
    wallets.set_last_fiat_update($scope);
    $scope.processWalletVars();
    $scope.$watch('wallet.current_subaccount', function(newValue, oldValue) {
        if (newValue != oldValue &&
                newValue !== undefined &&  // newValue === undefined on relogin
                oldValue !== undefined) $scope.wallet.update_balance();
    })
    $scope.$on('login', function() {
        $scope.$on('first_balance_updated', function (event, data) {
            $scope.wallet.balanceLoaded = true;
        });
        // after the handler in case there's a synchronous mock implementation
        $scope.wallet.update_balance(true);

        $scope.$on('transaction', function(event, data) {
            if (updating) return;
            updating = true;
            $scope.wallet.update_balance();
            if (data.value > 0) {
                notices.makeNotice('success', gettext('Bitcoin transaction received!'));
                sound.play(BASE_URL + "/static/sound/coinreceived.mp3", $scope);
            }
        });        
        if ($scope.wallet.expired_deposits && $scope.wallet.expired_deposits.length) {
            $scope.redeposit_modal = $uibModal.open({
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
                    notices.makeNotice('error', err.args[1]);
                }).finally(function() { $scope.generating_bitcoin_uri = false; });
            }
        };
    }

    $scope.show_url_qr = function(url) {
        gaEvent('Wallet', 'ShowUrlQRModal');
        $uibModal.open({
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
        var modal = $uibModal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_verify_mnemonic.html',
            scope: $scope
        });
    }

    $scope.$watch(function() { return $location.path(); }, function(newValue, oldValue) {
        $uibModalStack.dismissAll();
        if (newValue == '/') tx_sender.logout();  // logout on navigation to login page
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
        tx_sender.call("http://greenaddressit.com/vault/prepare_redeposit", txos_in,
                {rbf_optin: $scope.wallet.appearance.replace_by_fee, prevouts_mode: 'http'}).then(function(data) {
            wallets.sign_and_send_tx($scope, data, false, twofac_data).then(function() {
                deferred.resolve();
            }, function(err) {
                deferred.reject(err);
            });
        }, function(error) {
            deferred.reject(error.args[1]);
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
                [[$scope.wallet.expired_deposits[0].txhash, $scope.wallet.expired_deposits[0].out_n]],
                {rbf_optin: $scope.wallet.appearance.replace_by_fee,
                 prevouts_mode: 'http'}).then(function() {
            // prepare one to set appropriate tx data for 2FA
            return wallets.get_two_factor_code($scope, 'send_tx', null, true).then(function(twofac_data) {
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
