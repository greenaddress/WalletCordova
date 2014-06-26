angular.module('greenWalletServices', [])
.factory('focus', ['$rootScope', '$timeout', 'cordovaReady', function ($rootScope, $timeout, cordovaReady) {
   return function(name) {
        $timeout(function (){
            $rootScope.$broadcast('focusOn', name);
            if (window.cordova) {
                cordovaReady(function() {
                    window.plugins.SoftKeyboard.show();
                })();
            }
        });
   }
}]).factory('crypto', ['cordovaReady', '$q', function(cordovaReady, $q) {
    var pbkdf2_iterations = 10; //Not ideal, but limitations of using javascript
    var cryptoService = {};
    cryptoService.encrypt = function(data, password) {
        if (window.cordova && cordova.platformId == 'ios') {
            var deferred = $q.defer();
            cordovaReady(function() {
                cordova.exec(function(param) {
                    deferred.resolve(param);
                }, function(fail) {
                    console.log('cryptoService.encrypt failed: ' + fail)
                    deferred.resolve();
                }, "AES", "encrypt", [data, password]);
            })();
            return deferred.promise;
        } else {
            var salt = Bitcoin.CryptoJS.lib.WordArray.random(16);
            var key256Bits = Bitcoin.CryptoJS.PBKDF2(password, salt, {
                    keySize: 256/32, iterations: pbkdf2_iterations});
            var encrypted = Bitcoin.CryptoJS.AES.encrypt(data, key256Bits, {
                    mode: Bitcoin.CryptoJS.mode.CBC,
                    padding: Bitcoin.CryptoJS.pad.Iso10126,
                    iv: salt});
            return $q.when(Bitcoin.CryptoJS.enc.Base64.stringify(salt.concat(encrypted.ciphertext)));
        }
    }
    cryptoService.decrypt = function(data, password) {
        if (window.cordova && cordova.platformId == 'ios') {
            var deferred = $q.defer();
            cordovaReady(function() {
                cordova.exec(function(param) {
                    deferred.resolve(param);
                }, function(fail) {
                    console.log('cryptoService.encrypt failed: ' + fail)
                    deferred.resolve();
                }, "AES", "decrypt", [data, password]);
            })();
            return deferred.promise;
        } else {
            //iso10126 with pbkdf2_iterations iterations
            try {
                var parsed_data = Bitcoin.CryptoJS.enc.Base64.parse(data);
                var salt = Bitcoin.CryptoJS.lib.WordArray.create(parsed_data.words.splice(0, 4));
                parsed_data.sigBytes -= 16;
                var key256Bits = Bitcoin.CryptoJS.PBKDF2(password, salt, {
                        keySize: 256/32, iterations: pbkdf2_iterations});
                var decoded = Bitcoin.CryptoJS.AES.decrypt(
                        Bitcoin.CryptoJS.lib.CipherParams.create({ciphertext: parsed_data}),
                        key256Bits, {
                            mode: Bitcoin.CryptoJS.mode.CBC,
                            padding: Bitcoin.CryptoJS.pad.Iso10126,
                            iv: salt});
                if (decoded != null && decoded.sigBytes > 0) {
                    return $q.when(Bitcoin.CryptoJS.enc.Utf8.stringify(decoded));
                };
            } catch (e) {
                console.log(e);
            }
            return $q.when();
        }
    }
    return cryptoService;
}]).factory('autotimeout', ['$timeout', '$document', function($timeout, $document) {
    var timeoutms = 1000;
    var autotimeoutService = {promise: false, callbacks: []};

    var notifyObservers = function(){
        angular.forEach(autotimeoutService['callbacks'], function(callback){
            callback();
        });
    };
    var reset = function(amountminutes) {
        autotimeoutService.left = amountminutes * 1000 * 60;
    };

    var countdown = function() {
        if (autotimeoutService.left <= 0) {
            autotimeoutService.stop();
            window.location.reload();
        } else {
            autotimeoutService.left = autotimeoutService.left - timeoutms;
            notifyObservers();
            autotimeoutService.promise = $timeout(countdown, timeoutms);
        }
    };
    
    autotimeoutService.registerObserverCallback = function(callback){
        autotimeoutService['callbacks'].push(callback);
    };
    
    autotimeoutService.stop = function() {
        $document.find('body').off('mousemove keydown DOMMouseScroll mousewheel mousedown touchstart');
        if (autotimeoutService.promise) {
            $timeout.cancel(autotimeoutService.promise);
            autotimeoutService.promise = false;
        }
    };

    autotimeoutService.start = function(amountminutes) {
        autotimeoutService.stop();
        if (amountminutes != 0) {
            reset(amountminutes);
            autotimeoutService.promise = $timeout(countdown, timeoutms);
            $document.find('body').on('mousemove keydown DOMMouseScroll mousewheel mousedown touchstart', function() {
                try {
                    reset(amountminutes);
                } catch(err) {
                    // already logged out
                    console.log(err);
                    //autotimeoutService.stop();
                }
            });
        }
    };

    return autotimeoutService;

}]).factory('wallets', ['$q', '$rootScope', 'tx_sender', '$location', 'notices', '$modal', 'focus', 'crypto', 'gaEvent', 'storage', 'mnemonics', 'addressbook', 'autotimeout', 'social_types', 'sound', 'vibration',
        function($q, $rootScope, tx_sender, $location, notices, $modal, focus, crypto, gaEvent, storage, mnemonics, addressbook, autotimeout, social_types, sound, vibration) {
    var walletsService = {};
    var handle_double_login = function(retry_fun) {
        return $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_logout_other_session.html'
        }).result.then(function() {
            return retry_fun();
        });
    }
    walletsService.requireWallet = function($scope, dontredirect) {
        if (!$scope.wallet.hdwallet && !$scope.wallet.trezor_dev) {
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
                $scope.processWalletVars();  // update payment values with redir value
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
    var openInitialPage = function(wallet) {
        if ($location.search().redir) {
            $location.url($location.search().redir);
        } else if (window.IS_MOBILE || wallet.send_to_receiving_id || wallet.send_to_payment_request) {
            $location.path('/send');
        } else {
            $location.url('/info');
        }
    };
    walletsService._login = function($scope, hdwallet, mnemonic, signup, logout, path_seed, path) {
        var promise = tx_sender.login(logout), that = this;
        return promise.then(function(data) {
            if (data) {
                if (window.disableEuCookieComplianceBanner) {
                    disableEuCookieComplianceBanner();
                }
                tx_sender.wallet = $scope.wallet;
                $scope.wallet.hdwallet = hdwallet;
                $scope.wallet.trezor_dev = tx_sender.trezor_dev;
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
                if (!('sound' in $scope.wallet.appearance)) {
                    $scope.wallet.appearance.sound = true;
                }
                if (!('vibrate' in $scope.wallet.appearance)) {
                    $scope.wallet.appearance.vibrate = true;
                }
                vibration.state = $scope.wallet.appearance.vibrate;
                if (!('altimeout' in $scope.wallet.appearance)) {
                    $scope.wallet.appearance.altimeout = 20;
                }
                notices.makeNotice('success', gettext('Logged in!'));
                sound.play(BASE_URL + "/static/sound/coinreceived.mp3", $scope);
                autotimeout.start($scope.wallet.appearance.altimeout);
                $scope.wallet.privacy = data.privacy;
                $scope.wallet.limits = data.limits;
                $scope.wallet.unit = $scope.wallet.appearance.unit || 'mBTC';
                $scope.wallet.cache_password = data.cache_password;
                $scope.wallet.fiat_exchange = data.exchange;
                $scope.wallet.receiving_id = data.receiving_id;
                $scope.wallet.expired_deposits = data.expired_deposits;
                $scope.wallet.nlocktime_blocks = data.nlocktime_blocks;
                if (path) {
                    $scope.wallet.gait_path = path;
                } else {
                    $scope.wallet.gait_path_seed = path_seed;
                    $scope.wallet.gait_path = mnemonics.seedToPath(path_seed);
                }
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
                    openInitialPage($scope.wallet);
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
    }
    walletsService.login = function($scope, hdwallet, mnemonic, signup, logout, path_seed) {
        tx_sender.hdwallet = hdwallet;
        return this._login($scope, hdwallet, mnemonic, signup, logout, path_seed);
    };
    walletsService.login_trezor = function($scope, trezor_dev, path, signup, logout) {
        tx_sender.trezor_dev = trezor_dev;
        return this._login($scope, undefined, undefined, signup, logout, undefined, path, trezor_dev);
    }
    walletsService.loginWatchOnly = function($scope, token_type, token, logout) {
        var promise = tx_sender.loginWatchOnly(token_type, token, logout), that = this;
        promise = promise.then(function(json) {
            if (window.disableEuCookieComplianceBanner) {
                disableEuCookieComplianceBanner();
            }
            var data = JSON.parse(json);
            tx_sender.wallet = $scope.wallet;
            var hdwallet = new Bitcoin.HDWallet();
            hdwallet.network = cur_net;
            hdwallet.pub = new Bitcoin.ECPubKey(Bitcoin.convert.hexToBytes(data.public_key));
            hdwallet.chaincode = Bitcoin.convert.hexToBytes(data.chain_code);
            $scope.wallet.hdwallet = hdwallet;
            try {
                $scope.wallet.appearance = JSON.parse(data.appearance);
                if ($scope.wallet.appearance.constructor !== Object) $scope.wallet.appearance = {};
            } catch(e) {
                $scope.wallet.appearance = {};
            }
            if (!('sound' in $scope.wallet.appearance)) {
                $scope.wallet.appearance.sound = true;
            }
            if (!('vibrate' in $scope.wallet.appearance)) {
                $scope.wallet.appearance.vibrate = true;
            }
            if (!('altimeout' in $scope.wallet.appearance)) {
                $scope.wallet.appearance.altimeout = 20;
            }

            autotimeout.start($scope.wallet.appearance.altimeout);
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
    walletsService.getTransactions = function($scope, notifydata) {
        var transactions_key = $scope.wallet.receiving_id + 'transactions'
        var deferreds = [addressbook.load($scope), storage.get(transactions_key)];
        return $q.all(deferreds).then(function(results) {
            var cache = results[1];
            try {
                cache = JSON.parse(cache) || {items: []};
            } catch(e) {
                cache = {items: []};
            }
            if (cache.last_txhash) {
                return crypto.decrypt(cache.items, $scope.wallet.cache_password).then(function(decrypted) {
                    cache.items = JSON.parse(decrypted);
                    return walletsService._getTransactions($scope, cache, notifydata);
                });
            } else cache.items = [];
            return walletsService._getTransactions($scope, cache, notifydata);
        });
    };
    walletsService._getTransactions = function($scope, cache, notifydata) {
        var transactions_key = $scope.wallet.receiving_id + 'transactions';
        var d = $q.defer();
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

                var value = new Bitcoin.BigInteger('0'),
                    in_val = new Bitcoin.BigInteger('0'), out_val = new Bitcoin.BigInteger('0'),
                    redeemable_value = new Bitcoin.BigInteger('0'), sent_back_from, redeemable_unspent = false,
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
                            var bytes = Bitcoin.base58.decode(ep.ad);
                            var version = bytes[0];
                            var _external_social = version != Bitcoin.network[cur_net].p2shVersion;
                            external_social = external_social || _external_social;

                            if (ep.social_destination && external_social) {
                                pubkey_pointer = ep.pubkey_pointer;
                                if (!from_me) {
                                    redeemable_value = redeemable_value.add(new Bitcoin.BigInteger(ep.value));
                                    sent_back_from = ep.social_destination;
                                    redeemable_unspent = redeemable_unspent || !ep.is_spent;
                                }
                            } else {
                                value = value.add(new Bitcoin.BigInteger(ep.value));
                                ep.nlocktime = true;
                            }
                        }
                        else {
                            value = value.subtract(new Bitcoin.BigInteger(ep.value));
                        }
                    }
                    if (ep.is_credit) {
                        outputs.push(ep);
                        out_val = out_val.add(new Bitcoin.BigInteger(ep.value));
                        output_values[[tx.txhash, ep.pt_idx]] = new Bitcoin.BigInteger(ep.value);
                    } else { inputs.push(ep); in_val = in_val.add(new Bitcoin.BigInteger(ep.value)); }
                }
                if (value.compareTo(new Bitcoin.BigInteger('0')) > 0 || redeemable_value.compareTo(new Bitcoin.BigInteger('0')) > 0) {
                    if (notifydata && (tx.txhash == notifydata.txhash)) {
                        notices.makeNotice('success', gettext('Bitcoin transaction received!'));
                        sound.play(BASE_URL + "/static/sound/coinreceived.mp3", $scope);
                    }
                    positive = true;
                    if (redeemable_value.compareTo(new Bitcoin.BigInteger('0')) > 0) {
                        var description = gettext('Back from ') + sent_back_from;
                    } else {
                        var description = gettext('From ');
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
                        description += addresses.length ? addresses[0] : '';
                        if (addresses.length > 1) {
                            description += ', ...';
                        }
                    }
                } else {
                    negative = value.compareTo(new Bitcoin.BigInteger('0')) < 0;
                    var addresses = [];
                    var description = gettext('To ');
                    for (var j = 0; j < tx.eps.length; j++) {
                        var ep = tx.eps[j];
                        if (ep.is_credit && (!ep.is_relevant || ep.social_destination)) {
                            if (ep.social_destination && ep.social_destination_type != social_types.PAYMENTREQUEST) {
                                pubkey_pointer = ep.pubkey_pointer;
                                var bytes = Bitcoin.base58.decode(ep.ad);
                                var version = bytes[0];
                                var _external_social = version != Bitcoin.network[cur_net].p2shVersion;
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
                            } else if (ep.social_destination && ep.social_destination_type == social_types.PAYMENTREQUEST) {
                                if (addresses.indexOf(ep.social_destination) == -1) {
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
                var value_sort = new Bitcoin.BigInteger(Math.pow(10, 19).toString()).add(value).toString();
                while (value_sort.length < 20) value_sort = '0' + value_sort;
                retval.unshift({ts: new Date(tx.created_at.replace(' ', 'T')), txhash: tx.txhash, memo: tx.memo,
                             value_sort: value_sort, value: value, instant: tx.instant,
                             value_fiat: data.fiat_value ? value * data.fiat_value / Math.pow(10, 8) : undefined,
                             redeemable_value: redeemable_value, negative: negative, positive: positive,
                             description: description, external_social: external_social, unclaimed: unclaimed,
                             pubkey_pointer: pubkey_pointer, inputs: inputs, outputs: outputs,
                             fee: in_val.subtract(out_val).toString(),
                             nonzero: value.compareTo(new Bitcoin.BigInteger('0')) != 0,
                             redeemable: redeemable_value.compareTo(new Bitcoin.BigInteger('0')) > 0,
                             redeemable_unspent: redeemable_unspent,
                             sent_back: sent_back, block_height: tx.block_height,
                             confirmations: tx.block_height ? data.cur_block - tx.block_height + 1: 0,
                             has_payment_request: tx.has_payment_request});
                // tx.unclaimed is later used for cache updating
                tx.unclaimed = retval[0].unclaimed || (retval[0].redeemable && retval[0].redeemable_unspent);
            }
            crypto.encrypt(JSON.stringify(cache.items), $scope.wallet.cache_password).then(function(encrypted) {
                cache.items = encrypted;
                storage.set(transactions_key, JSON.stringify(cache));
            });

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
    var _sign_and_send_tx = function($scope, data, priv_der, twofactor, notify) {
        var d = $q.defer();
        var tx = Bitcoin.Transaction.deserialize(data.tx);
        var signatures = [];
        for (var i = 0; i < tx.ins.length; ++i) {
            (function(i) {
                if (data.prev_outputs[i].privkey) {
                    var key = $q.when(data.prev_outputs[i].privkey);
                } else {
                    var key = tx_sender.hdwallet;
                    if (priv_der) {
                        key = $q.when(key.derivePrivate(data.prev_outputs[i].branch)).then(function(key) {
                            return key.derivePrivate(data.prev_outputs[i].pointer);
                        });
                    } else {
                        key = $q.when(key.derive(data.prev_outputs[i].branch));
                        if (data.prev_outputs[i].subaccount) {
                            key = key.then(function(key) {
                                return key.derivePrivate(data.prev_outputs[i].subaccount);
                            });
                        }
                        key = key.then(function(key) {
                            return key.derive(data.prev_outputs[i].pointer);
                        });
                    }
                    key = key.then(function(key) {
                        return key.priv;
                    });
                }
                var sign = key.then(function(key) {
                    var script = new Bitcoin.Script(Bitcoin.convert.hexToBytes(data.prev_outputs[i].script));
                    var SIGHASH_ALL = 1;
                    var sign = key.sign(tx.hashTransactionForSignature(script, i, SIGHASH_ALL));
                    sign.push(SIGHASH_ALL);
                    return Bitcoin.convert.bytesToHex(sign);
                });
                signatures.push(sign);
            })(i);
        }
        $q.all(signatures).then(function(signatures) {
            tx_sender.call("http://greenaddressit.com/vault/send_tx", signatures, twofactor||null).then(function(data) {
                d.resolve();
                if (!twofactor) {
                    tx_sender.call("http://greenaddressit.com/login/get_spending_limits").then(function(data) {
                        $scope.wallet.limits.total = data.total;
                    });
                }
                if (notify !== false) {
                    sound.play(BASE_URL + "/static/sound/coinsent.mp3", $scope);
                    notices.makeNotice('success', notify || gettext('Bitcoin transaction sent!'));
                }
            }, function(reason) {
                d.reject();
                notices.makeNotice('error', gettext('Transaction failed: ') + reason.desc);
                sound.play(BASE_URL + "/static/sound/wentwrong.mp3", $scope);
            });
        }, d.reject);
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
                for (var key in $scope.twofactor_method_names) {
                    if (twofac_data[key] === true) {
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
        if ($scope && data.requires_2factor) {
            var d = $q.defer();
            walletsService.get_two_factor_code($scope, 'send_tx').then(function(twofac_data) {
                d.resolve(_sign_and_send_tx($scope, data, priv_der, twofac_data, notify));
            }, function(err) { d.reject(err); });
            return d.promise;
        } else {
            return _sign_and_send_tx($scope, data, priv_der, twofac_data, notify);
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
                                if (!$scope.wallet.hdwallet.seed_hex) {
                                    deferred.reject(gettext('Internal error')+': Missing seed');
                                    return;
                                }
                                if (password) {
                                    var data = JSON.stringify({'seed': $scope.wallet.hdwallet.seed_hex,
                                                               'path_seed': $scope.wallet.gait_path_seed,
                                                               'mnemonic': $scope.wallet.mnemonic});
                                    crypto.encrypt(data, password).then(function(encrypted) {
                                        storage.set('encrypted_seed', encrypted);
                                    });
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
            return $q.when(Bitcoin.HDWallet.fromSeedHex($scope.wallet.hdwallet.seed_hex, cur_net)).then(function(hdwallet) {
                hdwallet.seed_hex = $scope.wallet.hdwallet.seed_hex;
                return walletsService.login($scope||{wallet:{}}, hdwallet,
                        $scope.wallet.mnemonic, false, false, $scope.wallet.gait_path_seed).then(function() {
                    return do_create();
                });
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
}]).factory('tx_sender', ['$q', '$rootScope', 'cordovaReady', '$http', 'notices', 'gaEvent', '$location', 'autotimeout', 'device_id',
        function($q, $rootScope, cordovaReady, $http, notices, gaEvent, $location, autotimeout, device_id) {
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
                autotimeout.stop();
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
                        autotimeout.stop();
                        txSenderService.logout();
                        $location.path('/concurrent_login');
                    });
                }
                if (reason && reason.indexOf('WS-4001') != -1) {  // concurrent login on the same device
                    $rootScope.$apply(function() {
                        autotimeout.stop();
                        txSenderService.logout();
                        $location.path('/');
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
            if (hdwallet) {
                txSenderService.call('http://greenaddressit.com/login/get_challenge',
                        hdwallet.getAddress().toString()).then(function(challenge) {
                    var challenge_bytes = new Bitcoin.BigInteger(challenge).toByteArrayUnsigned();

                    // generate random path to derive key from - avoids signing using the same key twice
                    var max64int_hex = '';
                    while (max64int_hex.length < 16) max64int_hex += 'F';
                    var TWOPOWER64 = new Bitcoin.BigInteger(max64int_hex, 16).add(Bitcoin.BigInteger.ONE);
                    var random_path_hex = Bitcoin.ecdsa.getBigRandom(TWOPOWER64).toString(16);
                    while (random_path_hex.length < 16) random_path_hex = '0' + random_path_hex;
                    $q.when(hdwallet.subpath_for_login(random_path_hex)).then(function(subhd) {
                        $q.when(subhd.priv.sign(challenge_bytes)).then(function(signature) {
                            signature = Bitcoin.ecdsa.parseSig(signature);
                            d.resolve(device_id().then(function(devid) {
                                return txSenderService.call('http://greenaddressit.com/login/authenticate',
                                        [signature.r.toString(), signature.s.toString()], logout||false,
                                         random_path_hex, devid).then(function(data) {
                                    txSenderService.logged_in = data;
                                    return data;
                                });
                            }));
                        });
                    });
                });
            } else {  // trezor_dev
                var trezor_dev = txSenderService.trezor_dev;
                trezor_dev._typedCommonCall('GetAddress', 'Address', {
                    address_n: [],
                    coin_name: cur_net == 'testnet' ? 'Testnet' : 'Bitcoin'
                }).then(function (addr) {
                    txSenderService.call('http://greenaddressit.com/login/get_trezor_challenge',
                            addr.message.address).then(function(challenge) {

                        msg = Bitcoin.CryptoJS.enc.Hex.stringify(Bitcoin.CryptoJS.enc.Utf8.parse('greenaddress.it      login ' + challenge))
                        // generate random path to derive key from - avoids signing using the same key twice
                        var max64int_hex = '';
                        while (max64int_hex.length < 16) max64int_hex += 'F';
                        var TWOPOWER64 = new Bitcoin.BigInteger(max64int_hex, 16).add(Bitcoin.BigInteger.ONE);
                        var random_path_hex = Bitcoin.ecdsa.getBigRandom(TWOPOWER64).toString(16);
                        while (random_path_hex.length < 16) random_path_hex = '0' + random_path_hex;
                        var path_bytes = Bitcoin.convert.hexToBytes(random_path_hex);
                        var path = [];
                        for (var i = 0; i < 4; i++) {
                            path.push(+Bitcoin.BigInteger.fromByteArrayUnsigned(path_bytes.slice(0, 2)))
                            path_bytes.shift(); path_bytes.shift();
                        }
                        trezor_dev.signing = true;
                        trezor_dev._typedCommonCall('SignMessage', 'MessageSignature',
                                {'message': msg, address_n: path}).then(function(res) {
                            signature = Bitcoin.ecdsa.parseSigCompact(Bitcoin.convert.hexToBytes(res.message.signature));
                            trezor_dev.signing = false;
                            d.resolve(device_id().then(function(devid) {
                                return txSenderService.call('http://greenaddressit.com/login/authenticate',
                                        [signature.r.toString(), signature.s.toString(), signature.i.toString()], logout||false,
                                         random_path_hex, devid).then(function(data) {
                                    txSenderService.logged_in = data;
                                    return data;
                                });
                            }));
                        }, function(err) {
                            d.reject(err.message);
                            trezor_dev.signing = false;
                        });
                    });
                });
            }   
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
        txSenderService.trezor_dev = undefined;
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
}]).factory('facebook', ['$q', '$rootScope', 'cordovaReady', '$interval', function($q, $rootScope, cordovaReady, $interval) {
    if (!document.getElementById('fb-root')) return;

    var FB_deferred = $q.defer();
    var FB_promise = FB_deferred.promise;
    var initd = false;
    window.fbAsyncInit = function() {
        $interval.cancel(FB_interval_promise);
        cordovaReady(function() {
            FB_deferred.resolve();
        })();
    };
    if (window.cordova) {
        // fbAsyncInit is not called for some reason in Cordova, so we poll for FB
        var FB_interval_promise = $interval(function() {
            if (window.FB) {
                window.fbAsyncInit();
            }
        }, 100, 50);  // try for 5 seconds
    }

    cordovaReady(function() {
        var e = document.createElement('script');e.async = true;
        e.src = 'https://connect.facebook.net/en_US/all.js';
        document.getElementById('fb-root').appendChild(e);
    })();

    var logged_in = false;
    var login_deferred = $q.defer();
    FB_promise = FB_promise.then(function() {
        FB.Event.subscribe('auth.authResponseChange', function(response) {
            if (response.status == 'connected') {
                logged_in = true;
                $rootScope.safeApply(function() {
                    login_deferred.resolve();
                });
            }
        });

        if (window.cordova) {    
            FB.init({
                appId: FB_APP_ID,
                nativeInterface: CDV.FB,
                useCachedDialogs: false
            });
        } else {
            FB.init({
                appId: FB_APP_ID,
                status: true
            });
        }

        initd = true;
    });


    var facebookService = {};
    facebookService.login = function(loginstate) {
        if (loginstate.logging_in && !initd) return;
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
      queue.forEach(function (args) {
        fn.apply(args[0], args[1]);
      });
      impl = fn;
      navigator.splashscreen.hide();
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
        if (uri.indexOf("bitcoin:") == -1) {
            // not a URI
            return {};
        } else {
            if (uri.indexOf("?") == -1) {
                // no amount
                return {recipient: uri.split("bitcoin:")[1]};
            } else {
                var recipient =  uri.split("bitcoin:")[1].split("?")[0];
                var variables = parseKeyValue(uri.split('bitcoin:')[1].split('?')[1]);
                variables.recipient = recipient;
                return variables;
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
}]).factory('device_id', ['storage', function(storage) {
    var uuid4 = function() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {  
            var nums = new Uint32Array(1), r, v;
            window.crypto.getRandomValues(nums);
            r = nums[0] % 16,
            v = (c === 'x') ? r : (r&0x3|0x8);
            return v.toString(16);
        });
    }
    return function() {
        return storage.get('device_id').then(function(value) {
            if (!value) {
                var ret = uuid4();
                storage.set('device_id', ret)
                return ret;
            } else return value;
        })
    };
}]).factory('addressbook', ['$rootScope', 'tx_sender', 'storage', 'crypto', 'notices', '$q',
        function($rootScope, tx_sender, storage, crypto, notices, $q) {
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
        init_partitions: function(items) {
            var items = items || this.items, next_prefix, next_partition;
            var items_copy = [];
            for (var i = 0; i < items.length; i++) items_copy.push(items[i]);
            var PER_PAGE = 15;
            this.partitions = [];
            var get_name = function (item) {
                // works with 'unprocessed' and 'processed' items
                if (item.name) return item.name;
                else return item[0];
            }
            while (items_copy.length) {
                var prefix = next_prefix || get_name(items_copy[0])[0];
                var partition = next_partition || [];
                for (var i = 0; i < PER_PAGE; i++) {
                    if (!items_copy.length) break;
                    var next_item = this._process_item(items_copy.shift());
                    if (next_item) partition.push(next_item);
                    else i -= 1;  // crx facebook
                }
                if (items_copy.length) {
                    var next_prefix = get_name(items_copy[0])[0], next_partition = [];
                    while (next_prefix == partition[partition.length-1].name.substring(0, next_prefix.length) &&
                           next_prefix.length < get_name(items_copy[0]).length) {
                        next_prefix += get_name(items_copy[0])[next_prefix.length];
                        if (next_prefix.length == 3) {
                            while (partition.length && 
                                    partition[partition.length-1].name.substring(0, 3) == next_prefix) {
                                next_partition.push(partition.pop());
                            }
                            break;
                        }
                    }
                }
                if (partition.length) {
                    this.partitions.push([this.partitions.length+1, prefix, partition]);
                }
            }
        },
        _process_item: function(value) {
            var is_chrome_app = window.chrome && chrome.storage;
            if (value[3] == 'facebook') {
                var has_wallet = value[4];
                if (!has_wallet && is_chrome_app) return;  // can't send FB messages from Chrome app
                var href = 'https://www.facebook.com/' + value[1];
                return {name: value[0], type: value[3], address: value[1], has_wallet: has_wallet, href: href};
            } else {
                return {name: value[0], type: value[3], has_wallet: value[4], address: value[1]}; 
            }
        },
        update_with_items: function(items, $routeParams) {
            while (this.items.length) this.items.pop();
            this.reverse = {};
            if (!$routeParams) $routeParams = {};
            var that = this;
            items.sort(function(a, b) { return a[0].localeCompare(b[0]); });
            this.init_partitions(items);
            var i = 0;
            angular.forEach(items, function(value) {
                var item = that._process_item(value);
                if (!item) return;  // crx facebook
                if (value[3] != 'facebook') {
                    that.reverse[value[1]] = value[0];
                }
                that.items.push(item);
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
                var d;
                if (cache.hashed) {
                    d = crypto.decrypt(cache.items, $scope.wallet.cache_password).then(function(decrypted) {
                        that.update_with_items(JSON.parse(decrypted), $routeParams);
                    });
                    var requires_load = false;
                } else {
                    $rootScope.is_loading += 1;
                    d = $q.when();
                    requires_load = true;
                }

                return d.then(function() {
                    return tx_sender.call('http://greenaddressit.com/addressbook/read_all', cache.hashed).then(function(data) {
                        if (data.items) {
                            var items = data.items;
                            crypto.encrypt(JSON.stringify(data.items), $scope.wallet.cache_password).then(function(encrypted) {
                                cache.items = encrypted;
                                cache.hashed = data.hashed;
                                storage.set(addressbook_key, JSON.stringify(cache));
                            });
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
            });
        }
    };
}]).factory('vibration', [function() {
    // enable vibration support
    return {
            state: true,
            vibrate: function(data) {
                var that = this;
                navigator.vibrate = navigator.vibrate || navigator.webkitVibrate || navigator.mozVibrate || navigator.msVibrate;
                if (!navigator.vibrate && 'notification' in navigator) {
                    navigator.vibrate = navigator.notification.vibrate;
                }
                if (navigator.vibrate && that.state) {
                    navigator.vibrate(data);
                }
            }
    };

}]).factory('clipboard', ['$q', 'cordovaReady', function($q, cordovaReady) {
    return {
        copy: function(data) {
            var deferred = $q.defer();
            cordovaReady(function(){
                cordova.plugins.clipboard.copy(data, function() {
                    deferred.resolve(gettext('Copied'));
                }, function() {
                    deferred.reject(gettext('Error copying'));
                });
            })();
            return deferred.promise;
    }};

}]).factory('sound', ['cordovaReady', '$timeout', function(cordovaReady, $timeout) {
    return {
        play: function(src, $scope) {
            cordovaReady(function(){
                if (!$scope.wallet.appearance.sound) {
                    return;
                }
                if (window.cordova && typeof Media != "undefined") {
                    // Phonegap media
                    var mediaRes = new Media(src,
                        function onSuccess() {
                            // release the media resource once finished playing
                            mediaRes.release();
                        },
                        function onError(e){
                            console.log("error playing sound: " + JSON.stringify(e));
                        });
                    mediaRes.play();
                } else if (typeof Audio != "undefined") { 
                    //HTML5 Audio
                    $timeout(function() { new Audio(src).play(); });
                } else {
                    console.log("no sound API to play: " + src);
                }
            })();
    }};

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
                    deferred.reject
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
}]).factory('trezor', ['$q', '$interval', '$modal', function($q, $interval, $modal) {
    var promptPin = function(type, callback) {
        var scope, modal;

        scope = angular.extend($scope.$new(), {
            pin: '',
            type: type
        });

        modal = $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_trezor_pin.html',
            size: 'sm',
            windowClass: 'pinmodal',
            backdrop: 'static',
            keyboard: false,
            scope: scope
        });

        modal.result.then(
            function (res) { callback(null, res); },
            function (err) { callback(err); }
        );
    };

    return {
        getDevice: function() {
            var deferred = $q.defer();
            trezor.load({configUrl: '/static/trezor_config_signed.bin'}).then(function(api) {
                trezor_api = api;
                var tick = $interval(function() {
                    if (trezor_api.devices().length) {
                        $interval.cancel(tick);
                        trezor_dev = trezor_api.open(trezor_api.devices()[0]);
                        trezor_dev.on('pin', promptPin);
                        deferred.resolve(trezor_dev);
                    }
                }, 1000);
            });
            return deferred.promise;
        }
    }
}]).factory('bip38', ['$q', '$modal', 'mnemonics', 'focus', function($q, $modal, mnemonics, focus) {
    var bip38Service = {}, iframe;
    bip38Service.processMessage = function(message) {
        var is_chrome_app = window.chrome && chrome.storage;
        d = $q.defer();
        if (window.cordova) {
            var method, data, password = message.password;
            if (message.mnemonic_decrypted) {
                method = "encrypt_raw";
                data = message.mnemonic_decrypted;
            } else if (message.mnemonic_encrypted) {
                method = "decrypt_raw";
                data = message.mnemonic_encrypted;
            }
            cordovaReady(function() {
                cordova.exec(function(result) {
                    d.resolve({data: result});
                }, function(fail) {
                    d.reject(fail);
                }, "BIP38", method, [data, password]);
            })();
        } else if (is_chrome_app) {
            var process = function() {
                var listener = function(message) {
                    window.removeEventListener('message', listener);
                    d.resolve(message);
                };
                window.addEventListener('message', listener);
                iframe.contentWindow.postMessage(message, '*');
            };
            if (!iframe) {
                if (document.getElementById("id_iframe_bip38_service")) {
                    iframe = document.getElementById("id_iframe_bip38_service");
                    process();
                } else {
                    iframe = document.createElement("IFRAME"); 
                    iframe.onload = process;
                    iframe.setAttribute("src", "/bip38_sandbox.html");
                    iframe.setAttribute("class", "ng-hide");
                    iframe.setAttribute("id", "id_iframe_bip38_service");
                    document.body.appendChild(iframe); 
                }
            } else {
                process();
            }
        } else {
            var worker = new Worker("/static/js/bip38_worker.min.js");
            worker.onmessage = function(message) {
                d.resolve(message);
            }
            worker.postMessage(message);
        }
        return d.promise;
    }
    bip38Service.encrypt_mnemonic_modal = function($scope, seed) {
        var d = $q.defer();
        $scope.encrypt_password_modal = {
            encrypt: function() {
                this.error = undefined;
                if (!this.password) {
                    this.error = gettext('Please provide a password.');
                    return;
                }
                if (this.password != this.password_repeated) {
                    this.error = gettext('Passwords do not match.');
                    return;
                }
                this.encrypting = true;
                var that = this;
                bip38Service.processMessage({password: that.password, mnemonic_decrypted: seed}).then(function(message) {
                    mnemonics.toMnemonic(message.data).then(function(mnemonic) {
                        that.encrypting = false;
                        d.resolve(mnemonic);
                        modal.close();
                    });
                });
            }
        };
        var modal = $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signuplogin/modal_encryption_password.html',
            scope: $scope
        });
        modal.opened.then(function() { focus('encryptPasswordModal'); })
        return d.promise;
    };
    return bip38Service;
}]);
