angular.module('greenWalletServices', [])
.factory('focus', ['$rootScope', '$timeout', function ($rootScope, $timeout) {
   return function(name) {
       $timeout(function (){
           $rootScope.$broadcast('focusOn', name);
       });
   }
}]).factory('crypto', function() {
    var pbkdf2_iterations = 10; //Not ideal, but limitations of using javascript
    var cryptoService = {};
    cryptoService.encrypt = function(data, password) {
        return Crypto.AES.encrypt(data, password, { mode: new Crypto.mode.CBC(Crypto.pad.iso10126), iterations : pbkdf2_iterations});
    }
    cryptoService.decrypt = function(data, password) {
        //iso10126 with pbkdf2_iterations iterations
        try {
            var decoded = Crypto.AES.decrypt(data, password, { mode: new Crypto.mode.CBC(Crypto.pad.iso10126), iterations : pbkdf2_iterations});

            if (decoded != null && decoded.length > 0) {
                return decoded;
            };
        } catch (e) {
            console.log(e);
        }

        return null;
    }
    return cryptoService;
}).factory('wallets', ['$q', '$rootScope', 'tx_sender', '$location', 'notices', '$modal', 'focus', 'crypto', 'gaEvent', 'storage', 'mnemonics', 'addressbook',
        function($q, $rootScope, tx_sender, $location, notices, $modal, focus, crypto, gaEvent, storage, mnemonics, addressbook) {
    var walletsService = {};
    var handle_double_login = function(retry_fun) {
        return $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_logout_other_session.html'
        }).result.then(function() {
            return retry_fun();
        });
    }
    walletsService.requireWallet = function($scope, dontredirect) {
        if (!$scope.wallet.hdwallet) {
            if (!dontredirect) {
                var location = '/?redir=' + $location.path();
                var search = '';
                for (var key in $location.search()) {
                    if (i > 0) search += '&';
                    search += key + '=' + encodeURIComponent($location.search()[key]);
                }
                if (search) {
                    location += encodeURIComponent('?' + search);
                }
                $location.url(location);
            }
            return false;
        }
        return true;
    };
    walletsService.updateAppearance = function($scope, key, value) {
        var oldValue = $scope.wallet.appearance[key];
        $scope.wallet.appearance[key] = value;
        return tx_sender.call('http://greenaddressit.com/login/set_appearance', JSON.stringify($scope.wallet.appearance)).catch(function(e) {
            $scope.wallet.appearance[key] = oldValue;
            return $q.reject(e);
        });
    }
    walletsService.login = function($scope, hdwallet, mnemonic, signup, logout, path_seed) {
        tx_sender.hdwallet = hdwallet;
        var promise = tx_sender.login(logout), that = this;
        promise = promise.then(function(data) {
            if (data) {
                if (window.disableEuCookieComplianceBanner) {
                    disableEuCookieComplianceBanner();
                }
                tx_sender.wallet = $scope.wallet;
                $scope.wallet.hdwallet = hdwallet;
                $scope.wallet.mnemonic = mnemonic;
                if (data.last_login) {
                    $scope.wallet.last_login = data.last_login;
                }
                try {
                    $scope.wallet.appearance = JSON.parse(data.appearance);
                    if ($scope.wallet.appearance.constructor !== Object) $scope.wallet.appearance = {};
                } catch(e) {
                    $scope.wallet.appearance = {};
                }
                $scope.wallet.unit = $scope.wallet.appearance.unit || 'mBTC';
                $scope.wallet.cache_password = data.cache_password;
                $scope.wallet.fiat_exchange = data.exchange;
                $scope.wallet.receiving_id = data.receiving_id;
                $scope.wallet.expired_deposits = data.expired_deposits;
                $scope.wallet.nlocktime_blocks = data.nlocktime_blocks;
                $scope.wallet.gait_path_seed = path_seed;
                $scope.wallet.gait_path = mnemonics.seedToPath(path_seed);
                if (data.gait_path !== $scope.wallet.gait_path) {
                    tx_sender.call('http://greenaddressit.com/login/set_gait_path', $scope.wallet.gait_path).catch(function(err) {
                        if (err.uri != 'http://api.wamp.ws/error#NoSuchRPCEndpoint') {
                            notices.makeNotice('error', 'Please contact support (reference "sgp_error ' + err.desc + '")');
                        } else {
                            $scope.wallet.old_server = true;
                        }
                    });
                }
                if (!signup) {  // don't change URL on initial login in signup
                    if($location.search().redir) {
                        $location.url($location.search().redir);
                    } else {
                        $location.url('/info');
                    }
                }
                $rootScope.$broadcast('login');
            } else if (!signup) {  // signup has its own error handling
                notices.makeNotice('error', gettext('Login failed'));
            }
            return data;
        }, function(err) {
            if (err.uri == 'http://greenaddressit.com/error#doublelogin') {
                return handle_double_login(function() {
                    return that.login($scope, hdwallet, mnemonic, signup, true, path_seed);
                });
            } else {
                notices.makeNotice('error', gettext('Login failed') + ': ' + err.desc);
                return $q.reject(err);
            }
        });

        return promise;
    };
    walletsService.loginWatchOnly = function($scope, token_type, token, logout) {
        var promise = tx_sender.loginWatchOnly(token_type, token, logout), that = this;
        promise = promise.then(function(json) {
            if (window.disableEuCookieComplianceBanner) {
                disableEuCookieComplianceBanner();
            }
            var data = JSON.parse(json);
            tx_sender.wallet = $scope.wallet;
            $scope.wallet.hdwallet = new GAHDWallet({
                public_key_hex: data.public_key,
                chain_code_hex: data.chain_code
            });
            try {
                $scope.wallet.appearance = JSON.parse(data.appearance);
                if ($scope.wallet.appearance.constructor !== Object) $scope.wallet.appearance = {};
            } catch(e) {
                $scope.wallet.appearance = {};
            }
            $scope.wallet.unit = $scope.wallet.appearance.unit || 'mBTC';
            $scope.wallet.cache_password = data.cache_password;
            $scope.wallet.fiat_exchange = data.exchange;
            $scope.wallet.receiving_id = data.receiving_id;
            $location.url('/info/');
            $rootScope.$broadcast('login');
        }, function(err) {
            if (err.uri == 'http://greenaddressit.com/error#doublelogin') {
                return handle_double_login(function() {
                    return that.loginWatchOnly($scope, token_type, token, true);
                });
            } else {
                return $q.reject(err);
            }
        });
        return promise;
    };
    walletsService.getTransactions = function($scope) {
        var transactions_key = $scope.wallet.receiving_id + 'transactions'
        var deferreds = [addressbook.load($scope), storage.get(transactions_key)];
        return $q.all(deferreds).then(function(results) {
            var cache = results[1];
            return walletsService._getTransactions($scope, cache);
        });
    };
    walletsService._getTransactions = function($scope, cache) {
        var transactions_key = $scope.wallet.receiving_id + 'transactions';
        var d = $q.defer();  
        try {
            cache = JSON.parse(cache) || {items: []};
        } catch(e) {
            cache = {items: []};
        }
        if (cache.last_txhash) {
           cache.items = JSON.parse(crypto.decrypt(cache.items, $scope.wallet.cache_password));
        } else cache.items = [];
        $rootScope.is_loading += 1;
        var unclaimed = [];
        for (var i = 0; i < cache.items.length; i++) {
            var item = cache.items[i];
            if (item.unclaimed) {
                unclaimed.push(item.txhash);
            }
        }
        tx_sender.call('http://greenaddressit.com/txs/get_list', cache.last_txhash, unclaimed).then(function(data) {
            var retval = [];
            var output_values = {};
            var any_unconfirmed_seen = false;
            // prepend cache to the returned list
            for (var i = cache.items.length - 1; i >= 0; i--) {
                var item = cache.items[i];
                if (data.unclaimed[item.txhash]) {
                    // replace unclaimed in txcache
                    item = cache.items[i] = data.unclaimed[item.txhash];
                }
                data.list.unshift(cache.items[i]);
            }
            for (var i = 0; i < data.list.length; i++) {
                var tx = data.list[i], inputs = [], outputs = [];
                var num_confirmations = data.cur_block - tx.block_height + 1;
                if (i >= cache.items.length && tx.block_height && num_confirmations >= 6 &&
                        // Don't store in cache if there are 'holes' between confirmed transactions
                        // which can be caused by some older transactions getting confirmed later than
                        // newer ones. Storing such newer txs and marking last_txhash can cause those
                        // older txs to be missing from the list, being unconfirmed and not added to cache.
                        !any_unconfirmed_seen) {
                    // store confirmed txs in cache
                    cache.items.push(tx);
                    cache.last_txhash = tx.txhash;
                }
                any_unconfirmed_seen = num_confirmations < 6;

                var value = new BigInteger('0'), in_val = new BigInteger('0'), out_val = new BigInteger('0'),
                    redeemable_value = new BigInteger('0'), sent_back_from, redeemable_unspent = false,
                    pubkey_pointer, sent_back = false, from_me = false;
                var negative = false, positive = false, unclaimed = false, external_social = false;
                for (var j = 0; j < tx.eps.length; j++) {
                    var ep = tx.eps[j];
                    if (ep.is_relevant && !ep.is_credit) from_me = true;
                }
                for (var j = 0; j < tx.eps.length; j++) {
                    var ep = tx.eps[j];
                    if (ep.is_relevant) {
                        if (ep.is_credit) {                            
                            var bytes = Bitcoin.Base58.decode(ep.ad);
                            var version = bytes[0];
                            var _external_social = version != cur_coin_p2sh_version;
                            external_social = external_social || _external_social;

                            if (ep.social_destination && external_social) {
                                pubkey_pointer = ep.pubkey_pointer;
                                if (!from_me) {
                                    redeemable_value = redeemable_value.add(new BigInteger(ep.value));
                                    sent_back_from = ep.social_destination;
                                    redeemable_unspent = redeemable_unspent || !ep.is_spent;
                                }
                            } else {
                                value = value.add(new BigInteger(ep.value));
                                ep.nlocktime = true;
                            }
                        }
                        else value = value.subtract(new BigInteger(ep.value));
                    }
                    if (ep.is_credit) {
                        outputs.push(ep);
                        out_val = out_val.add(new BigInteger(ep.value));
                        output_values[[tx.txhash, ep.pt_idx]] = new BigInteger(ep.value);
                    } else { inputs.push(ep); in_val = in_val.add(new BigInteger(ep.value)); }
                }
                if (value.compareTo(new BigInteger('0')) > 0 || redeemable_value.compareTo(new BigInteger('0')) > 0) {
                    positive = true;
                    if (redeemable_value.compareTo(new BigInteger('0')) > 0) {
                        var description = gettext('Sent back from ') + sent_back_from;
                    } else {
                        var description = gettext('Received from ');
                        var addresses = [];
                        for (var j = 0; j < tx.eps.length; j++) {
                            var ep = tx.eps[j];
                            if (!ep.is_credit && !ep.is_relevant) {
                                if (ep.social_source) {
                                    if (addresses.indexOf(ep.social_source) == -1) {
                                        addresses.push(ep.social_source);
                                    }
                                } else {
                                    var ad = addressbook.reverse[ep.ad] || ep.ad;
                                    if (addresses.indexOf(ad) == -1) {
                                        addresses.push(ad);
                                    }
                                }
                            }
                        }
                        description += addresses.join(', ');
                    }
                } else {
                    negative = value.compareTo(new BigInteger('0')) < 0;
                    var addresses = [];
                    var description = gettext('Sent to ');
                    for (var j = 0; j < tx.eps.length; j++) {
                        var ep = tx.eps[j];
                        if (ep.is_credit && (!ep.is_relevant || ep.social_destination)) {
                            if (ep.social_destination) {
                                pubkey_pointer = ep.pubkey_pointer;
                                var bytes = Bitcoin.Base58.decode(ep.ad);
                                var version = bytes[0];
                                var _external_social = version != cur_coin_p2sh_version;
                                external_social = external_social || _external_social;
                                if (!ep.is_spent && ep.is_relevant) {
                                    unclaimed = true;
                                    addresses.push(ep.social_destination);
                                } else if (!ep.is_relevant && external_social) {
                                    sent_back = true;
                                    addresses.push(ep.ad);
                                } else {
                                    addresses.push(ep.social_destination);
                                }
                            } else {
                                var ad = addressbook.reverse[ep.ad] || ep.ad;
                                addresses.push(ad);
                            }
                        }
                    }
                    if(sent_back) {
                        description = gettext('Sent back to ')
                    }
                    if (!addresses.length) {
                        description = gettext('Re-deposited');
                    } else {
                        description += addresses.join(', ');
                    }
                }
                // prepend zeroes for sorting
                var value_sort = BigInteger.valueOf(Math.pow(10, 19)).add(value).toString();
                while (value_sort.length < 20) value_sort = '0' + value_sort;
                retval.unshift({ts: new Date(tx.created_at.replace(' ', 'T')), txhash: tx.txhash,
                             value_sort: value_sort, value: value, value_fiat: value * data.fiat_value / Math.pow(10, 8),
                             redeemable_value: redeemable_value, negative: negative, positive: positive,
                             description: description, external_social: external_social, unclaimed: unclaimed,
                             pubkey_pointer: pubkey_pointer, inputs: inputs, outputs: outputs,
                             fee: in_val.subtract(out_val).toString(),
                             nonzero: value.compareTo(new BigInteger('0')) != 0,
                             redeemable: redeemable_value.compareTo(new BigInteger('0')) > 0,
                             redeemable_unspent: redeemable_unspent,
                             sent_back: sent_back, block_height: tx.block_height,
                             confirmations: tx.block_height ? data.cur_block - tx.block_height + 1: 0});
                // tx.unclaimed is later used for cache updating
                tx.unclaimed = retval[0].unclaimed || (retval[0].redeemable && retval[0].redeemable_unspent);
            }
            cache.items = crypto.encrypt(JSON.stringify(cache.items), $scope.wallet.cache_password);
            storage.set(transactions_key, JSON.stringify(cache));

            d.resolve({fiat_currency: data.fiat_currency, list: retval,
                        populate_csv: function() {
                            var csv_list = [gettext('Time,Description,satoshis,')+this.fiat_currency];
                            for (var i = 0; i < Math.min(this.limit, this.list.length); i++) {
                                var item = this.list[i];
                                csv_list.push(item.ts + ',' + item.description.replace(',', '\'') + ',' + item.value + ',' + item.value_fiat);
                            }   
                            this.csv = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv_list.join('\n'));
                        },
                        output_values: output_values});
        }, function(err) {
            notices.makeNotice('error', err.desc);
        }).finally(function() { $rootScope.is_loading -= 1; });
        return d.promise
    };
    var _sign_and_send_tx = function(data, priv_der, twofactor, notify) {
        var d = $q.defer();
        var tx = decode_raw_tx(Crypto.util.hexToBytes(data.tx));
        var signatures = [];
        for (var i = 0; i < tx.ins.length; ++i) {
            if (data.prev_outputs[i].privkey) {
                var key = data.prev_outputs[i].privkey;
            } else {
                var key = tx_sender.hdwallet;
                key = key.subkey(data.prev_outputs[i].branch, priv_der, true);
                key = key.subkey(data.prev_outputs[i].pointer, priv_der, true);
                key = new Bitcoin.ECKey(key.secret_exponent);
            }
            var script = new Bitcoin.Script(Crypto.util.hexToBytes(data.prev_outputs[i].script));
            var sign = key.sign(tx.hashTransactionForSignature(script, i, SIGHASH_ALL));
            sign = Bitcoin.ECDSA.serializeSig(sign.r, sign.s);
            sign.push(SIGHASH_ALL);
            signatures.push(Crypto.util.bytesToHex(sign));
        }
        tx_sender.call("http://greenaddressit.com/vault/send_tx", signatures, twofactor||null).then(function(data) {
            d.resolve();
            if (notify !== false) {
                notices.makeNotice('success', notify || gettext('Bitcoin transaction sent!'));
            }
        }, function(reason) {
            d.reject();
            notices.makeNotice('error', gettext('Transaction failed: ') + reason.desc);
        });
        return d.promise;
    }
    walletsService.getTwoFacConfig = function($scope, force) {
        var d = $q.defer();
        if ($scope.wallet.twofac !== undefined && !force) {
            d.resolve($scope.wallet.twofac);
        } else {
            tx_sender.call('http://greenaddressit.com/twofactor/get_config').then(function(data) {
                $scope.wallet.twofac = data;
                d.resolve($scope.wallet.twofac);
            });
        }
        return d.promise;
    };
    walletsService.get_two_factor_code = function($scope, action, data) {
        var deferred = $q.defer();
        walletsService.getTwoFacConfig($scope).then(function(twofac_data) {
            if (twofac_data.any) {
                $scope.twofactor_method_names = {
                    'gauth': 'Google Authenticator',
                    'email': 'Email',
                    'sms': 'SMS',
                    'phone': gettext('Phone')
                };
                $scope.twofactor_methods = [];
                for (var key in twofac_data) {
                    if (twofac_data[key] === true && key != 'any') {
                        $scope.twofactor_methods.push(key);
                    }
                };
                var order = ['gauth', 'email', 'sms', 'phone'];
                $scope.twofactor_methods.sort(function(a,b) { return order.indexOf(a)-order.indexOf(b); })
                $scope.twofac = {
                    twofactor_method: $scope.twofactor_methods[0],
                    codes_requested: {},
                    request_code: function() {
                        var that = this;
                        this.requesting_code = true;
                        return tx_sender.call('http://greenaddressit.com/twofactor/request_' + this.twofactor_method,
                                action, data).then(function() {
                            that.codes_requested[that.twofactor_method] = true;
                            that.requesting_code = false;
                        }, function(err) {
                            notices.makeNotice('error', err.desc);
                            that.requesting_code = false;
                        });
                    }};
                var show_modal = function() {
                    var modal = $modal.open({
                        templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_2fa.html',
                        scope: $scope,
                        windowClass: 'twofactor'
                    });
                    modal.opened.then(function() { focus("twoFactorModal"); });
                    deferred.resolve(modal.result);
                };
                if ($scope.twofactor_methods.length == 1) {
                    if ($scope.twofactor_methods[0] == 'gauth') {
                        // just gauth - no request required
                        $scope.twofac.gauth_only = true;  // don't display the radio buttons
                                                          // (not required in 'else' because codes_requested takes care of it)
                        show_modal();
                    } else {
                        // just sth else than gauth - request it because user can't choose anything else anyway
                        $scope.twofac.twofactor_method = $scope.twofactor_methods[0];
                        $scope.twofac.request_code().then(function() {
                            show_modal();
                        })
                    }
                } else {
                    // more than one auth method available - allow the user to select
                    show_modal();
                }
            } else {
                return deferred.resolve(null);
            }
        });
        return deferred.promise;
    }
    walletsService.sign_and_send_tx = function($scope, data, priv_der, twofac_data, notify) {
        if ($scope) {
            var d = $q.defer();
            walletsService.get_two_factor_code($scope, 'send_tx').then(function(twofac_data) {
                d.resolve(_sign_and_send_tx(data, priv_der, twofac_data, notify));
            }, function(err) { d.reject(err); });
            return d.promise;
        } else {
            return _sign_and_send_tx(data, priv_der, twofac_data, notify);
        }
    }
    walletsService.addCurrencyConversion = function($scope, model_name) {
        var div = {'BTC': 1, 'mBTC': 1000, 'µBTC': 1000000}[$scope.wallet.unit];
        $scope.$watch(model_name+'.amount', function(newValue, oldValue) {
            if (newValue === oldValue) return;
            if ($scope[model_name].updated_by_conversion) {
                $scope[model_name].updated_by_conversion = false;
            } else {
                var oldFiat = $scope[model_name].amount_fiat;
                if (!newValue) {
                    $scope[model_name].amount_fiat = '';
                } else {
                    $scope[model_name].amount_fiat = newValue * $scope.wallet.fiat_rate / div;
                    $scope[model_name].amount_fiat = (Math.round($scope[model_name].amount_fiat * 100) / 100).toString();
                }
                if ($scope[model_name].amount_fiat !== oldFiat) {
                    $scope[model_name].updated_by_conversion = true;
                }
            }
        });
        $scope.$watch(model_name+'.amount_fiat', function(newValue, oldValue) {
            if (newValue === oldValue) return;
            if ($scope[model_name].updated_by_conversion) {
                $scope[model_name].updated_by_conversion = false;
            } else {
                var oldBTC = $scope[model_name].amount;
                if (!newValue) {
                    $scope[model_name].amount = '';
                } else {
                    $scope[model_name].amount = (div * newValue / $scope.wallet.fiat_rate).toString();
                }
                if ($scope[model_name].amount !== oldBTC) {
                    $scope[model_name].updated_by_conversion = true;
                }
            }
        });
    };
    walletsService.create_pin = function(pin, $scope) {
        var do_create = function() {
            var deferred = $q.defer();
            tx_sender.call('http://greenaddressit.com/pin/set_pin_login', pin, 'Primary').then(
                function(data) {
                    if (data) {
                        var pin_ident = tx_sender.pin_ident = data;
                        storage.set('pin_ident', pin_ident);
                        tx_sender.call('http://greenaddressit.com/pin/get_password', pin, data).then(
                            function(password) {
                                if (password) {
                                    var data = JSON.stringify({'seed': $scope.wallet.hdwallet.seed_hex,
                                                               'path_seed': $scope.wallet.gait_path_seed,
                                                               'mnemonic': $scope.wallet.mnemonic});
                                    storage.set('encrypted_seed', crypto.encrypt(data, password));
                                    tx_sender.pin = pin;
                                    deferred.resolve(pin_ident);
                                } else {
                                    deferred.reject(gettext('Failed retrieving password.'))
                                }
                            }, function(err) {
                                deferred.reject(err.desc);
                            });
                    } else {
                        deferred.reject();
                    }
                }, function(err) {
                    deferred.reject(err.desc);
                }
            );
            return deferred.promise;
        };
        if (!tx_sender.logged_in) {
            var hdwallet = new GAHDWallet({seed_hex: $scope.wallet.hdwallet.seed_hex});
            return walletsService.login($scope||{wallet:{}}, hdwallet,
                    $scope.wallet.mnemonic, false, false, $scope.wallet.gait_path_seed).then(function() {
                return do_create();
            });
        } else {  // already logged in
            return do_create();
        }
    };
    walletsService.askForLogout = function($scope, text) {
        $scope.ask_for_logout_text = text;
        return $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_logout.html',
            scope: $scope
        }).result;
    };
    return walletsService;
}]).factory('notices', ['$rootScope', '$timeout', function($rootScope, $timeout) {
    var notices = $rootScope.notices = [];
    var noticesService = {};
    noticesService.makeNotice = function(type, msg, timeout) {
        if (msg == null || msg.length == 0)
            return;

        console.log(msg);

        var data = {
            type: type,
            msg: msg
        };
        notices.push(data);

        if (timeout == null)
            timeout = 5000;

        if (timeout > 0) {
            $timeout(function() {
                for (var i = 0; i < notices.length; ++i) {
                    if (notices[i] === data) {
                        notices.splice(i, 1);
                    }
                }
            }, timeout);
        }
    };
    noticesService.setLoadingText = function(text, ifNotSet) {
        if (!ifNotSet || !$rootScope.loading_text) {
            $rootScope.loading_text = text;
        }
    };
    return noticesService;
}]).factory('tx_sender', ['$q', '$rootScope', 'cordovaReady', '$http', 'notices', 'gaEvent', '$location',
        function($q, $rootScope, cordovaReady, $http, notices, gaEvent, $location) {
    var rng = new SecureRandom();
    ab._Deferred = $q.defer;
    var txSenderService = {};
    if (window.Electrum) {
        if (window.cordova) {
            txSenderService.electrum = new Electrum($http, $q);
        } else {
            txSenderService.electrum = new Electrum();
            txSenderService.electrum.connectToServer();
        }
    }
    var session, calls = [];
    txSenderService.call = function() {
        var d = $q.defer();
        if (session) {
            session.call.apply(session, arguments).then(function(data) {
                $rootScope.$apply(function() { d.resolve(data); })
            }, function(err) {
                $rootScope.$apply(function() { d.reject(err); })
            });
        } else {
            if (disconnected) {
                disconnected = false;
                connect();
            }
            calls.push([arguments, d]);
        }
        return d.promise;
    };
    var isMobile = /Android|iPhone|iPad|iPod|Opera Mini/i.test(navigator.userAgent);
    if (window.cordova) {
        cordovaReady(function() {
            document.addEventListener("resume", function() {
                if (!txSenderService.wallet) return;
                session.close();  // reconnect on resume
                session = null;
                disconnected = true;
                txSenderService.wallet.update_balance();
                txSenderService.wallet.refresh_transactions();
            }, false);
        })();        
    } else if (isMobile && typeof document.addEventListener !== undefined) {
        // reconnect on tab shown in mobile browsers
        document.addEventListener("visibilitychange", function() {
            if (!document.hidden && txSenderService.wallet) {
                txSenderService.wallet.update_balance();
                txSenderService.wallet.refresh_transactions();
            }
        }, false);
    }
    var onAuthed = function(s) {
        session = s;
        session.subscribe('http://greenaddressit.com/tx_notify', function(topic, event) {
            gaEvent('Wallet', 'TransactionNotification');
            $rootScope.$broadcast('transaction', event);        });
        session.subscribe('http://greenaddressit.com/block_count', function(topic, event) {
            $rootScope.$broadcast('block', event);
        });
        var d1, d2;
        if (txSenderService.hdwallet && txSenderService.logged_in) {
            txSenderService.logged_in = false;
            d1 = txSenderService.login();
        } else if (txSenderService.watch_only) {
            d1 = txSenderService.loginWatchOnly(txSenderService.watch_only[0], txSenderService.watch_only[1]);
        } else {
            d1 = $q.when(true);
        }
        d1.catch(function(err) { 
            if (err.uri == 'http://greenaddressit.com/error#doublelogin') {
                if (txSenderService.wallet) txSenderService.wallet.clear();
                $location.path('/concurrent_login');
            } else {
                notices.makeNotice('error', gettext('An error has occured which forced us to log you out.'))
                if (txSenderService.wallet) txSenderService.wallet.clear();
                $location.path('/');
            }
        });
        if (txSenderService.pin_ident) {
            // resend PIN to allow PIN changes in the event of reconnect
            d2 = session.call('http://greenaddressit.com/pin/get_password',
                              txSenderService.pin, txSenderService.pin_ident);
        } else {
            d2 = $q.when(true);
        }
        $q.all([d1, d2]).then(function() {
            // missed calls queue
            while (calls.length) {
                var item = calls.shift();
                item[1].resolve(txSenderService.call.apply(session, item[0]));
            }
        }, function(err) {
            // missed calls queue - reject them as well
            // safeApply because txSenderService.login might've called $apply already
            $rootScope.safeApply(function() {
                while (calls.length) {
                    var item = calls.shift();
                    item[1].reject(err);
                }
            });
        });
    };
    var retries = 60, everConnected = false, disconnected = false;
    var connect = function() {
        ab.connect(wss_url,
            function(s) {
                everConnected = true;
                $http.get((window.root_url||'')+'/token/').then(function(response) {
                    var token = response.data;
                    s.authreq(token).then(function(challenge) {
                        var signature = s.authsign(challenge, token);
                        s.auth(signature).then(function(permissions) {
                            onAuthed(s);
                        });
                    });
                });
            },
            function(code, reason) {
                if (retries && !everConnected) {  // autobahnjs doesn't reconnect automatically if it never managed to connect
                    retries -= 1;
                    setTimeout(connect, 5000);
                    return;
                }
                if (reason && reason.indexOf('WS-4000') != -1) {
                    $rootScope.$apply(function() {
                        txSenderService.logout();
                        $location.path('/concurrent_login');
                    });
                }
                session = null;
            },
            {maxRetries: 60}
        );
    };
    cordovaReady(connect)();
    txSenderService.logged_in = false;
    txSenderService.login = function(logout) {
        var d = $q.defer();
        if (txSenderService.logged_in) {
            d.resolve(txSenderService.logged_in);
        } else {
            var hdwallet = txSenderService.hdwallet;
            txSenderService.call('http://greenaddressit.com/login/get_challenge',
                    hdwallet.getBitcoinAddress().toString()).then(function(challenge) {
                var challenge_bytes = new BigInteger(challenge).toByteArrayUnsigned();

                // generate random path to derive key from - avoids signing using the same key twice
                var max64int_hex = '';
                while (max64int_hex.length < 16) max64int_hex += 'F';
                var TWOPOWER64 = new BigInteger(max64int_hex, 16).add(BigInteger.ONE);
                var random_path_hex = Bitcoin.ECDSA.getBigRandom(TWOPOWER64, rng).toString(16);
                while (random_path_hex.length < 16) random_path_hex = '0' + random_path_hex;
                var signature = new Bitcoin.ECKey(hdwallet.subpath_for_login(random_path_hex).secret_exponent_bytes).sign(challenge_bytes);

                d.resolve(txSenderService.call('http://greenaddressit.com/login/authenticate',
                        [signature.r.toString(), signature.s.toString()], logout||false, random_path_hex).then(function(data) {
                    txSenderService.logged_in = data;
                    return data;
                }));
            });
        }
        return d.promise;
    };
    txSenderService.logout = function() {
        if (session) {
            session.close();
        }
        disconnected = true;
        txSenderService.logged_in = false;
        txSenderService.hdwallet = undefined;
        txSenderService.watch_only = undefined;
        if (txSenderService.wallet) txSenderService.wallet.clear();
    };
    txSenderService.loginWatchOnly = function(token_type, token, logout) {
        var d = $q.defer();
        txSenderService.call('http://greenaddressit.com/login/watch_only',
            token_type, token, logout||false).then(function(data) {
                txSenderService.watch_only = [token_type, token];
                d.resolve(data);
            }, function(err) {
                d.reject(err);
            });
        return d.promise;
    };
    txSenderService.change_pin = function(new_pin) {
        return txSenderService.call('http://greenaddressit.com/pin/change_pin_login',
                new_pin, txSenderService.pin_ident).then(function() {
            // keep new pin for reconnection handling
            txSenderService.pin = new_pin;
        });
    };
    return txSenderService;
}]).factory('facebook', ['$q', '$rootScope', 'cordovaReady', function($q, $rootScope, cordovaReady) {
    if (!window.FB) {
      return;
    }
    var logged_in = false;
    var login_deferred = $q.defer();

    FB.Event.subscribe('auth.authResponseChange', function(response) {
        if (response.status == 'connected') {
            logged_in = true;
            $rootScope.safeApply(function() {
                login_deferred.resolve();
            });
        }
    });

    if (window.cordova) {
        cordovaReady(function() {
            FB.init({
                appId: FB_APP_ID,
                nativeInterface: CDV.FB,
                useCachedDialogs: false
            });
        })();        
    } else {
        FB.init({
            appId: FB_APP_ID,
            status: true
        });
    }

    var facebookService = {};
    facebookService.login = function(loginstate) {
        if (loginstate.logging_in) return;
        if (logged_in) {
            loginstate.logged_in = true;
            return $q.when(true);
        }
        loginstate.logging_in = true;
        var deferred = $q.defer();
        FB.login(function(response) {
            $rootScope.$apply(function() {
                if (response.authResponse) {
                    loginstate.logged_in = true;
                    deferred.resolve();
                } else {
                    deferred.reject();
                }
                loginstate.logging_in = false;
            });
        }, {scope: ''});
        return deferred.promise;
    };

    facebookService.getUser = function() {
        login_deferred = login_deferred.then(function() {
            var inner_deferred = $q.defer();
            FB.api('/me', function(response) {
                $rootScope.$apply(function() {
                    inner_deferred.resolve(response);
                });
            });
            return inner_deferred.promise;
        });
        return login_deferred;
    };

    return facebookService;
}]).factory('reddit', ['$q', function($q) {
    var redditService = {
        getToken: function(scope) {
            var tokenDeferred = $q.defer();
            var state = Math.random();
            var left = screen.width / 2 - 500, top = screen.height / 2 - 300;
            if (window.location.hostname == 'localhost') {
                var redir = 'http://localhost:9908/reddit/';
            } else {
                var redir = 'https://'+window.location.hostname+'/reddit/';
            }
            var w = window.open('https://ssl.reddit.com/api/v1/authorize?client_id='+REDDIT_APP_ID+'&redirect_uri='+redir+'&response_type=code&scope='+scope+'&state=' + state,
                        '_blank', 'toolbar=0,menubar=0,width=1000,height=600,left='+left+',top='+top);
            var deferred = $q.defer();
            var interval = setInterval(function() { if (w.closed) { 
                clearInterval(interval);
                deferred.resolve(true);
            } }, 500);
            deferred.promise.then(function() {
                if (window._reddit_token) {
                    tokenDeferred.resolve(_reddit_token);
                    _reddit_token = undefined;
                } else {
                    tokenDeferred.resolve(null);
                }
            });
            return tokenDeferred.promise;
        }
    };
    return redditService;
}]).factory('cordovaReady', function cordovaReady() {
  return function (fn) {
    // cordovaReady is called even when there is no Cordova support, hence
    // the plain `return fn` below.

    // This is because WebSockets are implemented on Android in Cordova,
    // so the initial implementation was a generic wrapper which runs
    // code even without Cordova, to allow running the same WebSockets
    // code on desktop and Android.

    // (See the usage in js/greenwallet/services.js: ab.connect()
    // is wrapped inside cordovaReady, because it uses WebSockets)

    // Maybe it might be better to add some runEvenWithoutCordova
    // argument to cordovaReady for that WebSockets special case, 
    // and by default don't run anything on desktop from the function
    // returned there...
    if (!window.cordova) {
        return fn;
    }

    var queue = [];

    var impl = function () {
      queue.push([this, Array.prototype.slice.call(arguments)]);
    };

    document.addEventListener('deviceready', function () {
      navigator.splashscreen.hide();
      queue.forEach(function (args) {
        fn.apply(args[0], args[1]);
      });
      impl = fn;
    }, false);

    return function () {
      return impl.apply(this, arguments);
    };
  };
}).factory('hostname', function() {
    var is_chrome_app = window.chrome && chrome.storage;
    if (is_chrome_app || window.cordova) {
        return 'greenaddress.it';
    } else {
        return window.location.hostname.replace('cordova.', '').replace('cordova-t.', '')
    }
}).factory('gaEvent', function gaEvent() {
    return function(category, action, label) {
        if (window._gaq) {
            try {
                if (category == '_pageview') {
                    _gaq.push(['_trackPageview', action]);
                } else {
                    _gaq.push(['_trackEvent', category, action, label]);
                }
            } catch (e) {}
        }
    }
}).factory('parseKeyValue', function() {
    var tryDecodeURIComponent = function (value) {
        try {
            return decodeURIComponent(value);
        } catch(e) {
            // Ignore any invalid uri component
        }
    };
    return function parseKeyValue(keyValue) {
        var obj = {}, key_value, key;
        angular.forEach((keyValue || "").split('&'), function(keyValue){
            if ( keyValue ) {
            key_value = keyValue.split('=');
            key = tryDecodeURIComponent(key_value[0]);
            if ( key !== undefined ) {
                var val = (key_value[1] !== undefined) ? tryDecodeURIComponent(key_value[1]) : true;
                if (!obj[key]) {
                    obj[key] = val;
                } else if(toString.call(obj[key]) === '[object Array]') {
                    obj[key].push(val);
                } else {
                    obj[key] = [obj[key],val];
                }
            }
        }
      });
      return obj;
    };
}).factory('parse_bitcoin_uri', ['parseKeyValue', function(parseKeyValue) {
    return function parse_bitcoin_uri(uri) {
        // FIXME: Should do better parsing, checking label and message too
        if (uri.indexOf("bitcoin:") == -1) {
            // not an URI
            return [undefined, undefined];
        } else {
            if (uri.indexOf("?") == -1) {
                // no amount
                return [uri.split("bitcoin:")[1], undefined];
            } else {
                var recipient =  uri.split("bitcoin:")[1].split("?")[0];
                var variables = parseKeyValue(uri.split('bitcoin:')[1].split('?')[1]);
                return [recipient, variables.amount];
            }
        }
    }
}]).factory('storage', ['$q', function($q) {
    if (window.chrome && chrome.storage) {
        var noLocalStorage = false;
    } else {
        try {
            var noLocalStorage = !window.localStorage;
        } catch(e) {
            var noLocalStorage = true;
        }
    }
    var storageService = {
        noLocalStorage: noLocalStorage,
        set: function(key, value) {
            if (window.chrome && chrome.storage) {
                var set_value = {};
                set_value[key] = value;
                chrome.storage.local.set(set_value);
            } else {
                if(!noLocalStorage) {
                    localStorage.setItem(key, value);
                }
            }
        },
        get: function(key) {
            var d = $q.defer();
            if (window.chrome && chrome.storage) {
                chrome.storage.local.get(key, function(items) {
                    if (key.constructor === Array) {
                        d.resolve(items);
                    } else {
                        d.resolve(items[key]);
                    }
                });
            } else {
                if (key.constructor === Array) {
                    var ret = {};
                    if (!noLocalStorage) {
                        for (var i = 0; i < key.length; ++i) {
                            ret[key[i]] = localStorage.getItem(key[i]);
                        }
                    }
                    d.resolve(ret);
                } else {
                    if (!noLocalStorage) {
                        d.resolve(localStorage.getItem(key));
                    } else {
                        d.resolve();
                    }
                }
            }
            return d.promise;
        },
        remove: function(key) {
            if (window.chrome && chrome.storage) {
                chrome.storage.local.remove(key);
            } else {
                localStorage.removeItem(key);
            }
        }
    };
    return storageService;
}]).factory('addressbook', ['$rootScope', 'tx_sender', 'storage', 'crypto',
        function($rootScope, tx_sender, storage, crypto) {
    return {
        items: [],
        reverse: {},
        new_item: undefined,
        populate_csv: function() {
            var csv_list = [];
            for (var i = 0; i < this.items.length; i++) {
                var item = this.items[i];
                csv_list.push(item.name + ',' + (item.href || item.address));
            }
            this.csv = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv_list.join('\n'));
        },
        update_with_items: function(items, $routeParams) {
            while (this.items.length) this.items.pop();
            this.reverse = {};
            if (!$routeParams) $routeParams = {};
            var that = this;
            items.sort(function(a, b) { return a[0].localeCompare(b[0]); });
            var i = 0;
            var is_chrome_app = window.chrome && chrome.storage;
            angular.forEach(items, function(value) {
                if (value[3] == 'facebook') {
                    var has_wallet = value[4];
                    if (!has_wallet && is_chrome_app) return;  // can't send FB messages from Chrome app
                    var href = 'https://www.facebook.com/' + value[1];
                    that.items.push({name: value[0], type: value[3], address: value[1], has_wallet: has_wallet, href: href});
                } else {
                    that.items.push({name: value[0], type: value[3], has_wallet: value[4], address: value[1]});
                    that.reverse[value[1]] = value[0];
                }
                if (value[0] === $routeParams.name) $routeParams.page = Math.ceil((i+1)/20);
                i += 1;
            });
            that.num_pages = Math.ceil(that.items.length / 20);
            that.pages = [];
            for (var i = 1; i <= that.num_pages; i++) that.pages.push(i);
            that.populate_csv();
        },
        load: function($scope, $routeParams) {
            var addressbook_key = $scope.wallet.receiving_id + 'addressbook'
            var cache;
            var that = this;
            return storage.get(addressbook_key).then(function(cache) {
                try {
                    cache = JSON.parse(cache) || {};
                } catch(e) {
                    cache = {};
                }
                if (cache.hashed) {
                    that.update_with_items(JSON.parse(crypto.decrypt(cache.items, $scope.wallet.cache_password)),
                                           $routeParams);
                    var requires_load = false;
                } else {
                    $rootScope.is_loading += 1;
                    requires_load = true;
                }

                return tx_sender.call('http://greenaddressit.com/addressbook/read_all', cache.hashed).then(function(data) {
                    if (data.items) {
                        var items = data.items;
                        cache.items = crypto.encrypt(JSON.stringify(data.items), $scope.wallet.cache_password);
                        cache.hashed = data.hashed;
                        storage.set(addressbook_key, JSON.stringify(cache));
                        that.update_with_items(items, $routeParams);
                    }
                }, function(err) {
                    notices.makeNotice('error', gettext('Error reading address book: ') + err.desc);
                }).finally(function() {
                    if (requires_load) {
                        $rootScope.is_loading -= 1;
                    }
                });
            });
        }
    };
}]).factory('qrcode', ['$q', 'cordovaReady', function($q, cordovaReady) {
    var n = navigator, v, webkit = false, moz = false, gCtx, stream, gotGUMerror = false;
    return {
    stop_scanning: function($scope) {
        v.pause();
        stream.stop()
        $scope.scanning_qr_video = false;
    },
    scan: function($scope, $event, suffix) {
        var that = this;
        var deferred = $q.defer();
        if (window.cordova) {
            $event.preventDefault();
            cordovaReady(function()  {
                cordova.plugins.barcodeScanner.scan(
                    function (result) {
                        console.log("We got a barcode\n" +
                        "Result: " + result.text + "\n" +
                        "Format: " + result.format + "\n" +
                        "Cancelled: " + result.cancelled);
                        if (!result.cancelled && result.format == "QR_CODE") {
                              deferred.resolve(result.text);
                        } else {
                            if (result.cancelled) {
                                deferred.reject(gettext('Cancelled'));    
                            } else {
                                deferred.reject(gettext('Invalid format'));
                            }
                        }
                    }, 
                    function (error) {
                        deferred.reject(error);
                    }
                );
            })();
        } else {
            v = document.getElementById("v" + (suffix||''));
            qrcode.callback = function(result) {
                if(result === 'error decoding QR Code') {
                    deferred.reject(gettext('Could not process the QR code, the image may be blurry. Please try again.'));
                    return;
                }
                deferred.resolve(result);
            };
            function captureToCanvas() {
                try{
                    gCtx.drawImage(v,0,0);
                    try{
                        qrcode.decode();
                        that.stop_scanning($scope);
                    }
                    catch(e){       
                        console.log(e);
                        setTimeout(captureToCanvas, 500);
                    };
                }
                catch(e){       
                        console.log(e);
                        setTimeout(captureToCanvas, 500);
                };
            }
            var success = function(stream_) {
                $scope.$apply(function() {
                    $scope.scanning_qr_video = true;
                });
                stream = stream_;
                gCanvas = document.getElementById("qr-canvas");
                var w = 800, h = 600;
                gCanvas.style.width = w + "px";
                gCanvas.style.height = h + "px";
                gCanvas.width = w;
                gCanvas.height = h;
                gCtx = gCanvas.getContext("2d");
                gCtx.clearRect(0, 0, w, h);
                if(webkit)
                    v.src = window.webkitURL.createObjectURL(stream);
                else if(moz){
                    v.mozSrcObject = stream;
                    v.play();
                } else {
                    v.src = stream;
                }
                setTimeout(captureToCanvas, 500);
            }
            var error = function() {
                $scope.gotGUMerror = true; // for some reason dispatchEvent doesn't work inside error()
                deferred.reject(gettext('Access denied. Retry to scan from file.'));
            };
            var scan_input = function() {
                var qr = $event.target;
                angular.element(qr).on('change', function(event) {
                    if (event.target.files.length != 1 && event.target.files[0].type.indexOf("image/") != 0) {
                        notices.makeNotice('error', gettext('You must provide only one image file.'));
                        return;
                    }

                    // https://github.com/kyledrake/coinpunk/blob/master/public/js/coinpunk/controllers/tx.js#L195
                    /*! Copyright (c) 2013, Kyle Drake */
                    var canvas = document.createElement('canvas');
                    var context = canvas.getContext('2d');
                    var img = new Image();
                    img.onload = function() {
                        /*
                        Helpful URLs: 
                        http://hacks.mozilla.org/2011/01/how-to-develop-a-html5-image-uploader/
                        http://stackoverflow.com/questions/19432269/ios-html5-canvas-drawimage-vertical-scaling-bug-even-for-small-images
                      
                        There are a lot of arbitrary things here. Help to clean this up welcome.
                        
                        context.save();
                        context.scale(1e6, 1e6);
                        context.drawImage(img, 0, 0, 1e-7, 1e-7, 0, 0, 1e-7, 1e-7);
                        context.restore();
                        */

                        if((img.width == 2448 && img.height == 3264) || (img.width == 3264 && img.height == 2448)) {
                            canvas.width = 1024;
                            canvas.height = 1365;
                            context.drawImage(img, 0, 0, 1024, 1365);
                        } else if(img.width > 1024 || img.height > 1024) {
                            canvas.width = img.width*0.15;
                            canvas.height = img.height*0.15;
                            context.drawImage(img, 0, 0, img.width*0.15, img.height*0.15);
                        } else {
                            canvas.width = img.width;
                            canvas.height = img.height;
                            context.drawImage(img, 0, 0, img.width, img.height);
                        }
                        qrcode.decode(canvas.toDataURL('image/png'));
                    }

                    img.src = URL.createObjectURL(event.target.files[0]);
                });
            };
            var tryGUM = function(source) {
                if (n.getUserMedia && !$scope.gotGUMerror) {
                    n.getUserMedia({video: source, audio: false}, success, error);
                    $event.preventDefault();
                } else if (n.webkitGetUserMedia && !$scope.gotGUMerror) {
                    webkit = true;
                    n.webkitGetUserMedia({video: source, audio: false}, success, error);
                    $event.preventDefault();
                } else if (n.mozGetUserMedia && !$scope.gotGUMerror) {
                    moz = true;
                    n.mozGetUserMedia({video: source, audio: false}, success, error);
                    $event.preventDefault();
                } else {
                    scan_input();
                }
            };
            if (window.MediaStreamTrack && MediaStreamTrack.getSources && !$scope.gotGUMerror) {
                $event.preventDefault();
                MediaStreamTrack.getSources(function(sources) {
                    var found = false;
                    for (var i = 0; i < sources.length; i++) {
                        if (sources[i].kind == 'video' && sources[i].facing == 'environment') {
                            found = true;
                            tryGUM({optional: [{sourceId: sources[i].id}]});
                            break;
                        }
                    }
                    if (!found) tryGUM(true);
                });
            } else {
                tryGUM(true);
            }
        }
        return deferred.promise;
    }};
}]);