angular.module('greenWalletControllers', [])
.controller('WalletController', ['$scope', 'tx_sender', '$modal', 'notices', 'gaEvent', '$location', 'wallets', '$http', '$timeout', '$q', 'parse_bitcoin_uri', 'parseKeyValue', 'backButtonHandler',
        function WalletController($scope, tx_sender, $modal, notices, gaEvent, $location, wallets, $http, $timeout, $q, parse_bitcoin_uri, parseKeyValue, backButtonHandler) {
    // appcache:
    applicationCache.addEventListener('updateready', function() {
        $scope.$apply(function() {
            $scope.update_available = true;
        });
    });
    $scope.update_now = function() {
        wallets.askForLogout($scope, gettext('You need to log out to update cache.')).then(function() {
            window.applicationCache.swapCache();
            window.location.reload();
        });
    };
    $scope.logout = function() {
        wallets.askForLogout($scope).then(function() {
            var filtered_intent = $scope.wallet.filtered_intent;
            clearwallet();
            tx_sender.logout();
            if (filtered_intent) navigator.app.exitApp();
            else $location.path('/');
        });
    };
    var updating = true, updating_txs = false;
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
        window.WalletControllerInitVars = {
            redeem_key: destPath.slice(8).replace(/\//g, ''),
            redeem_amount: destAmount
        };
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
        destUri = decodeURIComponent(destUri);
        var parsed_uri = parse_bitcoin_uri(destUri);
        var initVars = window.WalletControllerInitVars = {
            send_to_receiving_id_bitcoin_uri: destUri
        };    
        initVars.send_to_receiving_id = parsed_uri[0];
        initVars.send_to_receiving_id_amount = Bitcoin.Util.parseValue(parsed_uri[1]).toString();
    }
    var clearwallet = function() {
        $scope.wallet = {
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
            refresh_transactions: function() {
                if (updating_txs) return;
                updating_txs = true;
                wallets.getTransactions($scope).then(function(data) {
                    $scope.wallet.transactions = data;
                }).finally(function() { updating_txs = false; });
            },
            clear: clearwallet,
            get_tx_output_value: function(txhash, i) {
                if (tx_sender.electrum) {
                    var d = $q.defer();
                    return tx_sender.electrum.issueTransactionGet(txhash).then(function(rawtx) {
                        var bytes = decode_raw_tx(Crypto.util.hexToBytes(rawtx)).outs[i].value;
                        bytes.reverse();
                        return BigInteger.fromByteArrayUnsigned(bytes);
                    }, function(err) {
                        return $q.reject(err);
                    });
                    return d.promise;
                } else {
                    var is_chrome_app = window.chrome && chrome.storage;
                    // don't allow transactions in Chrome app or Cordova when no Electrum is available
                    if (window.cordova || is_chrome_app) return $q.reject(gettext('Electrum setup failed'));
                    return $q.when($scope.wallet.transactions.output_values[[txhash, i]]);
                }
            },
            send_to_receiving_id: window.location.href.indexOf(LANG+'/pay/') != -1 ||
                                  window.location.href.indexOf(LANG+'/uri/?uri=bitcoin') != -1 ||
                                  (window.WalletControllerInitVars && WalletControllerInitVars.send_to_receiving_id),
            signuplogin_header: BASE_URL + '/' + LANG + '/wallet/partials/signuplogin/header_wallet.html'
        };
    };
    clearwallet();
    if ($location.search().filtered_intent === '1') {
        backButtonHandler.pushHandler(backButtonHandler.exitAppHandler);
        $scope.wallet.filtered_intent = true;
    }
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
    if (window.WalletControllerInitVars) {
        angular.extend($scope.wallet, WalletControllerInitVars);
    }
    if ($scope.wallet.send_to_receiving_id) {
        $scope.wallet.signuplogin_header = BASE_URL + '/' + LANG + '/wallet/partials/signuplogin/header_pay.html'
    }
    if ($scope.wallet.redeem_key) {
        $scope.wallet.signuplogin_header = BASE_URL + '/' + LANG + '/wallet/partials/signuplogin/header_redeem.html'
    }
    $scope.$on('login', function() {
        $scope.wallet.update_balance(true);
        $scope.wallet.refresh_transactions();
        $scope.$on('transaction', function(event, data) {
            if (updating) return;
            updating = true;
            $scope.wallet.update_balance();
            $scope.wallet.refresh_transactions();
        });
        if ($scope.wallet.expired_deposits && $scope.wallet.expired_deposits.length) {
            $modal.open({
                templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_redeposit.html',
                controller: 'RedepositController',
                scope: $scope
            });
        }
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

    $scope.$watch(function() { return $location.path(); }, function(newValue, oldValue) {
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
        redeposit($scope.wallet.expired_deposits).then(function() {
            notices.makeNotice('success', gettext('Re-depositing successful!'));
        }, function(err) {
            notices.makeNotice('error', err);
        });
    };
    $scope.redeposit_multiple_tx = function() {
        return wallets.get_two_factor_code($scope).then(function(twofac_data) {
            var promise = $q.when();
            for (var i = 0; i < $scope.wallet.expired_deposits.length; ++i) {
                (function(i) { promise = promise.then(function() {
                    return redeposit([$scope.wallet.expired_deposits[i]], twofac_data);
                }, function(err) {
                    return $q.reject(err);
                });})(i);
            }
            promise.then(function() {
                notices.makeNotice('success', gettext('Re-depositing successful!'));
            }, function(err) {
                notices.makeNotice('error', err);
            });
            return promise;
        });
    };
}]);
