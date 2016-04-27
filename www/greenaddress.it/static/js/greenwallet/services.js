angular.module('greenWalletServices', [])
.factory('focus', ['$rootScope', '$timeout', 'cordovaReady', function ($rootScope, $timeout, cordovaReady) {
   return function(name) {
        $timeout(function (){
            $rootScope.$broadcast('focusOn', name);
            /* doesn't work very well
            if (window.cordova) {
                cordovaReady(function() {
                    window.plugins.SoftKeyboard.show();
                })();
            } */
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
            var salt = Bitcoin.randombytes(16);
            var key256Bits = Bitcoin.pbkdf2.pbkdf2Sync(
                password,
                salt,
                pbkdf2_iterations,
                256/8
            );
            var cipher = Bitcoin.aes.createCipheriv(
                'aes-256-cbc',
                key256Bits,
                salt
            );
            cipher.end(data);
            return $q.when(Bitcoin.Buffer.Buffer.concat([
                salt, cipher.read()
            ]).toString('base64'));
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
            try {
                var parsed_data = new Bitcoin.Buffer.Buffer(data, 'base64');
                var salt = parsed_data.slice(0, 16);
                parsed_data = parsed_data.slice(16);
                var key256Bits = Bitcoin.pbkdf2.pbkdf2Sync(
                    password,
                    salt,
                    pbkdf2_iterations,
                    256/8
                );
                var cipher = Bitcoin.aes.createDecipheriv(
                    'aes-256-cbc',
                    key256Bits,
                    salt
                );
                cipher.setAutoPadding(false);
                cipher.end(parsed_data);
                var decoded = cipher.read();
                // ignore padding bytes for backwards compatibility,
                // because our old implementation used the iso10126 padding:
                var padding = decoded[decoded.length-1];
                decoded = decoded.slice(0, decoded.length-padding);
                if (decoded != null) {
                    return $q.when(decoded.toString('utf-8'));
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
            var is_chrome_app = window.chrome && chrome.storage;
            if (is_chrome_app) {
                chrome.runtime.reload();
            } else {
                window.location.reload();
            }
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

}]).factory('blind', ['branches', function(branches) {
    var service = {};
    service._unblindOutValue = function($scope, out, scanning_key) {
        var secexp_buf = scanning_key.d.toBuffer();
        var secexp = Module._malloc(32);
        var nonce = Module._malloc(33);
        var nonce_res = Module._malloc(32);
        var pubkey_p = Module._malloc(64);
        var p_arr = Array.from(new Bitcoin.BigInteger(''+pubkey_p).toBuffer());
        while (p_arr.length < 4) p_arr.unshift(0);
        for (var i = 0; i < 32; ++i) {
            setValue(secexp+i, secexp_buf[i], 'i8');
        }
        for (var i = 0; i < 33; ++i) {
            setValue(nonce + i, out.nonce_commitment[i], 'i8');
        }
        if (1 != Module._secp256k1_ec_pubkey_parse(
            Module.secp256k1ctx,
            pubkey_p,
            nonce,
            33
        )) {
            throw new Error('secp256k1 EC pubkey parse failed');
        }
        if (1 != Module._secp256k1_ecdh(
            Module.secp256k1ctx,
            nonce_res,
            pubkey_p,
            secexp
        )) {
            throw new Error('secp256k1 ECDH failed');
        }
        var nonce_buf = new Bitcoin.Buffer.Buffer(32);
        for (var i = 0; i < 32; ++i) {
            nonce_buf[i] = getValue(nonce_res + i, 'i8') & 0xff;
        }
        nonce_buf = Bitcoin.bitcoin.crypto.sha256(nonce_buf);
        for (var i = 0; i < 32; ++i) {
            setValue(nonce_res + i, nonce_buf[i], 'i8');
        }
        var blinding_factor_out = Module._malloc(32);
        var amount_out = Module._malloc(8);
        var min_value = Module._malloc(8);
        var max_value = Module._malloc(8);
        var msg_out = Module._malloc(4096);
        var msg_size = Module._malloc(4);
        var commitment = Module._malloc(33);
        for (var i = 0; i < 33; ++i) {
            setValue(commitment + i, out.commitment[i], 'i8');
        }
        var range_proof = Module._malloc(out.range_proof.length);
        for (var i = 0; i < out.range_proof.length; ++i) {
            setValue(range_proof + i, out.range_proof[i], 'i8');
        }
        var rewindRes = Module._secp256k1_rangeproof_rewind(
            Module.secp256k1ctx,
            blinding_factor_out,
            amount_out,
            msg_out,
            msg_size,
            nonce_res,
            min_value,
            max_value,
            commitment,
            range_proof,
            out.range_proof.length
        );
        if (rewindRes != 1) {
            throw "Invalid transaction."
        }
        var ret = [];
        for (var i = 0; i < 8; ++i) {
            ret[8-i-1] = getValue(amount_out+i, 'i8') & 0xff;
        }
        var val = Bitcoin.BigInteger.fromBuffer(
            new Bitcoin.Buffer.Buffer(ret)
        );
        return {
            value: ''+(+val),
            blinding_factor_out: blinding_factor_out
        };
    };
    service.unblindOutValue = function($scope, out, subaccount, pubkey_pointer) {
        var key = $q.when($scope.wallet.hdwallet);
        if (subaccount) {
            key = key.then(function(key) {
                return key.deriveHardened(branches.SUBACCOUNT);
            }).then(function(key) {
                return key.deriveHardened(subaccount);
            })
        }
        return key.then(function(key) {
            return key.deriveHardened(branches.BLINDED)
        }).then(function(branch) {
            return branch.deriveHardened(pubkey_pointer);
        }).then(function(scanning_node) {
            return service._unblindOutValue(
                $scope, out, scanning_node.keyPair
            );
        });
    }
    return service;
}]).factory('wallets', ['$q', '$rootScope', 'tx_sender', '$location', 'notices', '$uibModal', 'focus', 'crypto', 'gaEvent', 'storage', 'mnemonics', 'addressbook', 'autotimeout', 'social_types', 'sound', '$interval', '$timeout', 'branches', 'user_agent', '$http', 'blind',
        function($q, $rootScope, tx_sender, $location, notices, $uibModal, focus, crypto, gaEvent, storage, mnemonics, addressbook, autotimeout, social_types, sound, $interval, $timeout, branches, user_agent, $http, blind) {
    var walletsService = {};
    var handle_double_login = function(retry_fun) {
        return $uibModal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_logout_other_session.html'
        }).result.then(function() {
            return retry_fun();
        });
    }
    walletsService.requireWallet = function($scope, dontredirect) {
        if (!$scope.wallet.hdwallet && !$scope.wallet.trezor_dev && !$scope.wallet.btchip) {
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
    var openInitialPage = function(wallet, has_txs) {
        if ($location.search().redir) {
            $location.url($location.search().redir);
        } else if (!has_txs) {
            $location.path('/receive');
        } else if (window.IS_MOBILE || wallet.send_to_receiving_id || wallet.send_to_payment_request) {
            $location.path('/send');
        } else {
            $location.url('/info');
        }
    };
    walletsService._login = function($scope, hdwallet, mnemonic, signup, logout, path_seed, path, double_login_callback) {
        var d = $q.defer(), that = this;
        tx_sender.login(logout, false, user_agent($scope.wallet)).then(function(data) {
            if (data) {
                if (window.disableEuCookieComplianceBanner) {
                    disableEuCookieComplianceBanner();
                }
                tx_sender.wallet = $scope.wallet;
                $scope.wallet.hdwallet = hdwallet;
                $scope.wallet.trezor_dev = tx_sender.trezor_dev;
                $scope.wallet.btchip = tx_sender.btchip;
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
                $scope.wallet.fee_estimates = data.fee_estimates;
                $scope.wallet.rbf = data.rbf;
                if (!('sound' in $scope.wallet.appearance)) {
                    $scope.wallet.appearance.sound = true;
                }
                if (!('pgp' in $scope.wallet.appearance)) {
                    $scope.wallet.appearance.pgp = "";
                }
                if (!('altimeout' in $scope.wallet.appearance)) {
                    $scope.wallet.appearance.altimeout = 20;
                }
                if (data.rbf && !('replace_by_fee' in $scope.wallet.appearance)) {
                    $scope.wallet.appearance.replace_by_fee = data.rbf;
                }
                sound.play(BASE_URL + "/static/sound/coinreceived.mp3", $scope);
                autotimeout.start($scope.wallet.appearance.altimeout);
                $scope.wallet.privacy = data.privacy;
                $scope.wallet.limits = data.limits;
                $scope.wallet.subaccounts = [
                    {pointer: 0, name: gettext("Main")}
                ].concat(data.subaccounts);
                $scope.wallet.assets = data.assets;
                $scope.wallet.current_subaccount = $scope.wallet.appearance.current_subaccount || 0;
                $scope.wallet.unit = $scope.wallet.appearance.unit || 'mBTC';
                $scope.wallet.cache_password = data.cache_password;
                $scope.wallet.fiat_exchange = data.exchange;
                $scope.wallet.fiat_exchange_extended = $scope.exchanges[data.exchange];
                $scope.wallet.receiving_id = data.receiving_id;
                $scope.wallet.expired_deposits = data.expired_deposits;
                $scope.wallet.nlocktime_blocks = data.nlocktime_blocks;
                if (data.gait_path) {
                    $scope.wallet.gait_path = data.gait_path;
                } else if (path) {
                    $scope.wallet.gait_path = path;
                } else if (path_seed) {
                    $scope.wallet.gait_path_seed = path_seed;
                    $scope.wallet.gait_path = mnemonics.seedToPath(path_seed);
                }
                if (!data.gait_path) {  // *NOTE*: don't change the path after signup, because it *will* cause locked funds
                    tx_sender.call('http://greenaddressit.com/login/set_gait_path', $scope.wallet.gait_path).catch(function(err) {
                        if (err.uri != 'http://api.wamp.ws/error#NoSuchRPCEndpoint') {
                            notices.makeNotice('error', 'Please contact support (reference "sgp_error ' + err.args[1] + '")');
                        } else {
                            $scope.wallet.old_server = true;
                        }
                    });
                }
                if (!signup) {  // don't change URL on initial login in signup
                    openInitialPage($scope.wallet, data.has_txs);
                }
                $rootScope.$broadcast('login');
            } else if (!signup) {  // signup has its own error handling
                d.reject();
                return;
            }
            d.resolve(data);
        }).catch(function(e) { d.reject(e); });
        return d.promise.catch(function(err) {
            if (err && err.uri == 'http://greenaddressit.com/error#doublelogin') {
                return handle_double_login(function() {
                    if (double_login_callback) double_login_callback();
                    return that.login($scope, hdwallet, mnemonic, signup, true, path_seed);
                });
            } else {
                notices.makeNotice('error', gettext('Login failed') + (err && err.args && err.args[1] && (': ' + err.args[1]) || ''));
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
        var that = this;
        return trezor_dev.getPublicKey([]).then(function(pubkey) {
            var pk = pubkey.message.node.public_key;
            pk = pk.toHex ? pk.toHex() : pk;
            var keyPair = new Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(
                new Bitcoin.Buffer.Buffer(pk, 'hex'),
                cur_net
            );
            tx_sender.trezor_address = keyPair.getAddress();
            var cc = pubkey.message.node.chain_code;
            cc = cc.toHex ? cc.toHex() : cc;
            var chainCode = new Bitcoin.Buffer.Buffer(cc, 'hex');
            var hdwallet = new Bitcoin.bitcoin.HDNode(keyPair, chainCode);
            tx_sender.hdwallet = hdwallet;
            return that._login($scope, hdwallet, undefined, signup, logout, undefined, path);
        });
    };
    walletsService.login_btchip = function($scope, btchip, btchip_pubkey, double_login_callback, signup) {
        tx_sender.btchip = btchip;
        tx_sender.btchip_address = btchip_pubkey.bitcoinAddress.value;
        var keyPair = new Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(
            new Bitcoin.Buffer.Buffer(
                btchip_pubkey.publicKey.toString(HEX),
                'hex'
            ),
            cur_net
        );
        var chainCode = new Bitcoin.Buffer.Buffer(
            btchip_pubkey.chainCode.toString(HEX), 'hex'
        );
        keyPair.compressed = true;
        var hdwallet = new Bitcoin.bitcoin.HDNode(
            keyPair,
            chainCode
        );
        tx_sender.hdwallet = hdwallet;
        if (signup) {
            var path_d = btchip.app.getWalletPublicKey_async("18241'").then(function(result) {
                var ecPub = new Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(new Bitcoin.Buffer.Buffer(result.publicKey.toString(HEX), 'hex'));
                ecPub.compressed = true;
                var extended = result.chainCode.toString(HEX) + ecPub.getPublicKeyBuffer().toString('hex');
                extended = new Bitcoin.Buffer.Buffer(extended, 'hex');
                var path = Bitcoin.hmac('sha512', 'GreenAddress.it HD wallet path').update(extended).digest();
                return path.toString('hex');
            });
        } else path_d = $q.when();
        var that = this;
        return path_d.then(function(path) {
            return that._login($scope, hdwallet, undefined, signup, false, undefined, path, undefined, double_login_callback);
        });
    };
    walletsService.loginWatchOnly = function($scope, token_type, token, logout) {
        var promise = tx_sender.loginWatchOnly(token_type, token, logout), that = this;
        promise = promise.then(function(json) {
            // add simple watchOnly flag so that we don't need to check values manually
            $scope.wallet.watchOnly = true;

            if (window.disableEuCookieComplianceBanner) {
                disableEuCookieComplianceBanner();
            }

            var data = JSON.parse(json);
            tx_sender.wallet = $scope.wallet;
            var hdwallet = new Bitcoin.bitcoin.HDNode(
                Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(
                    new Bitcoin.Buffer.Buffer(data.public_key, 'hex'),
                    cur_net
                ),
                new Bitcoin.Buffer.Buffer(data.chain_code, 'hex')
            );
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
            if (!('pgp' in $scope.wallet.appearance)) {
                $scope.wallet.appearance.pgp = "";
            }
            if (!('altimeout' in $scope.wallet.appearance)) {
                $scope.wallet.appearance.altimeout = 20;
            }

            autotimeout.start($scope.wallet.appearance.altimeout);
            $scope.wallet.unit = $scope.wallet.appearance.unit || 'mBTC';
            $scope.wallet.subaccounts = [
                {pointer: 0, name: gettext("Main")}
            ].concat(data.subaccounts);
            console.log($scope.wallet.subaccounts);
            $scope.wallet.assets = data.assets;
            $scope.wallet.current_subaccount = 0;
            $scope.wallet.cache_password = data.cache_password;
            $scope.wallet.fiat_exchange = data.exchange;
            $scope.wallet.receiving_id = data.receiving_id;
            if (data.has_txs) {
                $location.url('/info/');
            } else {
                $location.url('/receive/');
            }
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
    walletsService.getTransactions = function($scope, notifydata, query, sorting, date_range, subaccount) {
        return addressbook.load($scope).then(function() {
            return walletsService._getTransactions($scope, notifydata, null, query, sorting, date_range, subaccount);
        });
    };
    var parseSocialDestination = function(social_destination) {
        try {
            var data = JSON.parse(social_destination);
            if (data.type == 'voucher') return gettext('Voucher');
            else return social_destination;
        } catch (e) {
            return social_destination;
        }
    };
    var unblindOutputs = function($scope, txData, rawTxs) {
        var deferreds = [];
        var tx = Bitcoin.contrib.transactionFromHex(txData.data);
        for (var i = 0; i < txData.eps.length; ++i) {
            (function(ep) {
                if (ep.value === null && (ep.is_relevant || ep.pubkey_pointer)) {
                    // e.pubkey_pointer !== null means it's our ep, can be
                    // from different subaccount than currently processed
                    var txhash, pt_idx, out, subaccount;
                    if (ep.is_credit) {
                        txhash = txData.txhash;
                        pt_idx = ep.pt_idx;
                        out = tx.outs[ep.pt_idx];
                        subaccount = ep.subaccount;
                    } else {
                        txhash = ep.prevtxhash;
                        pt_idx = ep.previdx;
                        out = Bitcoin.contrib.transactionFromHex(
                            rawTxs[ep.prevtxhash]
                        ).outs[pt_idx];
                        subaccount = ep.prevsubaccount;
                    }
                    var key =
                        'unblinded_value_' + txhash + ':' + pt_idx;
                    var d = storage.get(key).then(function(value) {
                        if (value === null) {
                            return blind.unblindOutValue(
                                $scope, out, subaccount || 0, ep.pubkey_pointer
                            ).then(function(data) {
                                ep.value = data.value;
                                storage.set(key, data.value);
                            });
                        } else {
                            ep.value = value;
                        }
                    })
                    deferreds.push(d);
                }
            })(txData.eps[i]);
        }
        return $q.all(deferreds);
    }
    walletsService._getTransactions = function($scope, notifydata, page_id, query, sorting, date_range, subaccount) {
        var transactions_key = $scope.wallet.receiving_id + 'transactions';
        var d = $q.defer();
        $rootScope.is_loading += 1;
        var unclaimed = [];

        if (sorting) {
            var sort_by = sorting.order_by;
            if (sorting.reversed) { sort_by = '-'+sort_by; }
        } else {
            var sort_by = null;
        }
        sorting = sorting || {order_by: 'ts', reversed: true};
        var end = date_range && date_range[1] && new Date(date_range[1]);
        if (end) end.setDate(end.getDate() + 1);
        var date_range_iso = date_range && [date_range[0] && date_range[0].toISOString(),
                                            end && end.toISOString()];
        var args = ['http://greenaddressit.com/txs/get_list_v2',
            page_id, query, sort_by, date_range_iso, subaccount];
        if (cur_net.isAlpha) {
            // return prev data
            args.push(true);
        }
        var call = tx_sender.call.apply(tx_sender, args);

        if (cur_net.isAlpha) {
            call = call.then(function(data) {
                var deferreds = [];
                var valid = {};
                for (var i = 0; i < data.list.length; i++) {
                    (function(i) {
                        var tx = data.list[i];
                        tx.data = data.data[tx.txhash];
                        valid[i] = true;
                        deferreds.push(unblindOutputs($scope, tx, data.data)
                                .catch(function(e) {
                            if (e !== "Invalid transaction.") {
                                throw e;
                            } else {
                                // skip invalid transactions
                                valid[i] = false;
                            }
                        }));
                    })(i);
                }
                return $q.all(deferreds).then(function() {
                    var orig_list = data.list;
                    data.list = [];
                    for (var i = 0; i < orig_list.length; ++i) {
                        if (valid[i]) data.list.push(orig_list[i]);
                    }
                    return data;
                });
            });
        }

        call.then(function(data) {
            $scope.wallet.cur_block = data.cur_block;
            var retval = [];
            var any_unconfirmed_seen = false;
            var asset_name = null;
            for (var i = 0; i < data.list.length; i++) {
                var tx = data.list[i], inputs = [], outputs = [];
                var asset_id = tx.eps[0].asset_id;
                if (asset_id) {
                    var num_confirmations = data.cur_block[asset_id] - tx.block_height + 1;
                    asset_name = $scope.wallet.assets[asset_id];
                } else {
                    var num_confirmations = data.cur_block - tx.block_height + 1;
                }

                any_unconfirmed_seen = any_unconfirmed_seen || (num_confirmations < 6 && !tx.double_spent_by);

                var value = new Bitcoin.BigInteger('0'),
                    in_val = new Bitcoin.BigInteger('0'), out_val = new Bitcoin.BigInteger('0'),
                    redeemable_value = new Bitcoin.BigInteger('0'), sent_back_from, redeemable_unspent = false,
                    pubkey_pointer, sent_back = false, from_me = false, tx_social_destination, tx_social_value;
                var negative = false, positive = false, unclaimed = false, external_social = false;
                for (var j = 0; j < tx.eps.length; j++) {
                    var ep = tx.eps[j];
                    if (ep.is_relevant && !ep.is_credit) from_me = true;
                }
                for (var j = 0; j < tx.eps.length; j++) {
                    var ep = tx.eps[j];
                    if (ep.is_relevant) {
                        if (ep.is_credit) {
                            var bytes = Bitcoin.bs58.decode(ep.ad);
                            var version = bytes[0];
                            var _external_social = version != cur_net.scriptHash
                            external_social = external_social || _external_social;

                            if (ep.social_destination && external_social) {
                                pubkey_pointer = ep.pubkey_pointer;
                                if (!from_me) {
                                    redeemable_value = redeemable_value.add(new Bitcoin.BigInteger(ep.value));
                                    sent_back_from = parseSocialDestination(ep.social_destination);
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
                    } else { inputs.push(ep); in_val = in_val.add(new Bitcoin.BigInteger(ep.value)); }
                }
                if (value.compareTo(new Bitcoin.BigInteger('0')) > 0 || redeemable_value.compareTo(new Bitcoin.BigInteger('0')) > 0) {
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
                                try {
                                    tx_social_destination = JSON.parse(ep.social_destination);
                                    tx_social_value = ep.value;
                                } catch (e) {
                                }
                                pubkey_pointer = ep.pubkey_pointer;
                                var bytes = Bitcoin.bs58.decode(ep.ad);
                                var version = bytes[0];
                                var _external_social = version != cur_net.scriptHash;
                                external_social = external_social || _external_social;
                                if (!ep.is_spent && ep.is_relevant) {
                                    unclaimed = true;
                                    addresses.push(parseSocialDestination(ep.social_destination));
                                } else if (!ep.is_relevant && external_social) {
                                    sent_back = true;
                                    addresses.push(ep.ad);
                                } else {
                                    addresses.push(parseSocialDestination(ep.social_destination));
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
                retval.push({ts: new Date(tx.created_at.replace(' ', 'T')), txhash: tx.txhash, memo: tx.memo,
                             value_sort: value_sort, value: value, instant: tx.instant,
                             value_fiat: data.fiat_value ? value * data.fiat_value / Math.pow(10, 8) : undefined,
                             redeemable_value: redeemable_value, negative: negative, positive: positive,
                             description: description, external_social: external_social, unclaimed: unclaimed,
                             description_short: addresses.length ? addresses.join(', ') : description,
                             pubkey_pointer: pubkey_pointer, inputs: inputs, outputs: outputs, fee: tx.fee,
                             nonzero: value.compareTo(new Bitcoin.BigInteger('0')) != 0,
                             redeemable: redeemable_value.compareTo(new Bitcoin.BigInteger('0')) > 0,
                             redeemable_unspent: redeemable_unspent,
                             sent_back: sent_back, block_height: tx.block_height,
                             confirmations: tx.block_height ? num_confirmations: 0,
                             has_payment_request: tx.has_payment_request,
                             double_spent_by: tx.double_spent_by, replaced_by: tx.replaced_by,
                             replacement_of: [],
                             rawtx: cur_net.isAlpha ? data.data[tx.txhash] : tx.data,
                             social_destination: tx_social_destination, social_value: tx_social_value,
                             asset_id: asset_id, asset_name: asset_name, size: tx.size,
                             fee_per_kb: Math.round(tx.fee/(tx.size/1000)),
                             rbf_optin: tx.rbf_optin});
                // tx.unclaimed is later used for cache updating
                tx.unclaimed = retval[0].unclaimed || (retval[0].redeemable && retval[0].redeemable_unspent);
            }
            var hash2tx = {};
            for (var i = 0; i < retval.length; ++i) {
                hash2tx[retval[i].txhash] = retval[i];
            }
            var new_retval = [];
            for (var i = 0; i < retval.length; ++i) {
                var merged = false;
                if (retval[i].replaced_by && retval[i].replaced_by.length > 0) {
                    var replaced_by = retval[i].replaced_by;
                    for (var j = 0; j < replaced_by.length; ++j) {
                        var tx = hash2tx[replaced_by[j]];
                        if (tx && !(tx.replaced_by && tx.replaced_by.length)) {
                            tx.replacement_of.push(retval[i]);
                            merged = true;
                            break;
                        }
                    }
                }
                if (!merged) {
                    new_retval.push(retval[i]);
                }
            }
            retval = new_retval;
            d.resolve({fiat_currency: data.fiat_currency, list: retval, sorting: sorting, date_range: date_range, subaccount: subaccount,
                        populate_csv: function() {
                            var csv_list = [gettext('Time,Description,satoshis,%s,txhash,fee,memo').replace('%s', this.fiat_currency)];
                            for (var i = 0; i < this.list.length; i++) {
                                var item = this.list[i];
                                csv_list.push(item.ts + ',' + item.description.replace(',', '\'') + ',' + item.value + ',' + item.value_fiat + ',' + item.txhash + ',' + item.fee + ',' + item.memo);
                            }
                            this.csv = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv_list.join('\n'));
                        },
                        next_page_id: data.next_page_id,
                        fetch_next_page: function() {
                            var that = this;
                            walletsService._getTransactions($scope, notifydata, that.next_page_id, query, that.sorting, that.date_range, that.subaccount).then(function(result) {
                                that.list = that.list.concat(result.list);
                                that.next_page_id = result.next_page_id;
                            });
                        },
                        sort_by: function(sorting) {
                            var that = this;
                            walletsService._getTransactions($scope, notifydata, null, query, sorting, that.date_range, that.subaccount).then(function(result) {
                                that.sorting = sorting;
                                if (sorting.order_by == 'ts' && sorting.reversed) {
                                    that.pending_from_notification = false;
                                    that.pending_conf_from_notification = false;
                                }
                                that.list = result.list;
                                that.next_page_id = result.next_page_id;
                            });
                        }});
        }, function(err) {
            notices.makeNotice('error', err.args[1]);
            d.reject(err);
        }).finally(function() { $rootScope.decrementLoading(); });
        return d.promise
    };
    walletsService.send_confidential_tx = function($scope, recipient, satoshis) {
        if (satoshis !== 'ALL') {
            satoshis = new Bitcoin.BigInteger(satoshis);
        }
        var recipient_scanning_pubkey = recipient.slice(2, 35);
        var version;
        if (cur_net === Bitcoin.bitcoin.networks.bitcoin) {
            version = 10;
        } else {
            version = 25;
        }
        var unspent_found = Bitcoin.BigInteger.ZERO, utxo_num = 0;
        var needed_unspent = [];
        var fee = new Bitcoin.BigInteger('10000');
        var utxos = $scope.wallet.utxo[$scope.wallet.current_subaccount];
        while (satoshis == 'ALL' ||
                unspent_found.compareTo(satoshis.add(fee)) < 0) {
            if (utxo_num >= utxos.length) {
                if (satoshis == 'ALL' && unspent_found.compareTo(fee) > 0) {
                    // spend all (if enough for fee)
                    break;
                } else {
                    return $q.reject(gettext("Not enough money"));
                }
            }
            var utxo = utxos[utxo_num];
            unspent_found = unspent_found.add(new Bitcoin.BigInteger(
                utxo.data.value));
            needed_unspent.push(utxo);
            utxo_num += 1;
        }
        if (satoshis == 'ALL') {
            satoshis = unspent_found.subtract(fee);
        }
        var input_blinds_and_change = [];
        for (var i = 0; i < needed_unspent.length; ++i) {
            (function(utxo) {
                input_blinds_and_change.push(
                    blind.unblindOutValue(
                        $scope, utxo.out,
                        $scope.wallet.current_subaccount,
                        utxo.data.pubkey_pointer
                    ).then(function(data) {
                        return data.blinding_factor_out;
                    })
                );
            })(needed_unspent[i]);
        }
        var change_value = unspent_found.subtract(satoshis).subtract(fee);
        if (change_value.compareTo(Bitcoin.BigInteger.ZERO) > 0) {
            input_blinds_and_change.push(
                tx_sender.call(
                    'http://greenaddressit.com/vault/fund',
                    $scope.wallet.current_subaccount, true, true
                ).then(function(data) {
                    var key = $q.when($scope.wallet.hdwallet);
                    if ($scope.wallet.current_subaccount) {
                        key = key.then(function(key) {
                            return key.deriveHardened(branches.SUBACCOUNT);
                        }).then(function(key) {
                            return key.deriveHardened($scope.wallet.current_subaccount);
                        })
                    }
                    return key.then(function(key) {
                        return key.deriveHardened(branches.BLINDED);
                    }).then(function(branch) {
                        return branch.deriveHardened(data.pointer);
                    }).then(function(blinded_key) {
                        return tx_sender.call(
                            'http://greenaddressit.com/vault/set_scanning_key',
                            $scope.wallet.current_subaccount,
                            data.pointer,
                            Array.from(blinded_key.keyPair.getPublicKeyBuffer())
                        ).then(function() {
                            return blinded_key;
                        })
                    }).then(function(blinded_key) {
                        return [
                            blinded_key.keyPair.getPublicKeyBuffer(),
                            Bitcoin.bitcoin.crypto.hash160(
                                new Bitcoin.Buffer.Buffer(data.script, 'hex')
                            )
                        ];
                    });
                })
            );
        }
        return $q.all(input_blinds_and_change).then(function(input_blinds) {
            var main_out = {
                value: satoshis,
                to_version: recipient[1],
                to_scanning_pubkey: recipient.slice(2, 35),
                to_hash: recipient.slice(35)
            };
            var outs;
            if (change_value.compareTo(Bitcoin.BigInteger.ZERO) > 0) {
                var change_idx = Bitcoin.randombytes(1)[0] % 2;
                var change = input_blinds.pop();
                outs = [null, null];
                outs[change_idx] = {
                    value: change_value,
                    to_version: cur_net.scriptHash,
                    to_scanning_pubkey: change[0],
                    to_hash: change[1]
                };
                outs[1-change_idx] = main_out;
            } else {
                outs = [main_out];
            }
            var all = (needed_unspent.length + outs.length);
            var blindptrs = Module._malloc(4 * all);
            var cur_blindptr = 4 * needed_unspent.length;
            for (var i = 0; i < all; ++i) {
                if (i < needed_unspent.length) {
                    setValue(blindptrs + 4*i, input_blinds[i], '*');
                } else {
                    var cur = Module._malloc(32);
                    setValue(blindptrs + 4*i, cur, '*');
                    var rand = Bitcoin.randombytes(32);
                    for (var j = 0; j < 32; ++j) {
                        setValue(cur + j, rand[j], 'i8');
                    }
                }
            }
            for (var i = 0; i < outs.length; ++i) {
                if (i == outs.length - 1) {
                    if (1 != Module._secp256k1_pedersen_blind_sum(
                        Module.secp256k1ctx,
                        getValue(blindptrs + 4 * (all - 1), '*'),
                        blindptrs,
                        all - 1,
                        needed_unspent.length
                    )) {
                        throw new Error('secp256k1 pedersen blind sum failed');
                    }
                }
                var commitment = Module._malloc(33);
                if (1 != Module._secp256k1_pedersen_commit(
                    Module.secp256k1ctx,
                    commitment,
                    getValue(blindptrs + cur_blindptr, '*'),
                    +outs[i].value.mod(Bitcoin.BigInteger('2').pow(32)),
                    +outs[i].value.divide(Bitcoin.BigInteger('2').pow(32))
                )) {
                    throw new Error('secp256k1 Pedersen commit failed');
                }
                var commitment_buf = new Bitcoin.Buffer.Buffer(33);
                for (var j = 0; j < 33; ++j) {
                    commitment_buf[j] = getValue(
                        commitment + j, 'i8'
                    ) & 0xff;
                }
                var rangeproof_len = Module._malloc(4);
                var len = 5134;
                var rangeproof = Module._malloc(len);
                var rangeproof_len_buf = new Bitcoin.BigInteger(''+len).toBuffer();
                while (rangeproof_len_buf.length < 4) {
                    rangeproof_len_buf = Bitcoin.Buffer.Buffer.concat([
                        new Bitcoin.Buffer.Buffer([0]),
                        rangeproof_len_buf
                    ]);
                }
                for (var j = 0; j < 4; ++j) {
                    setValue(
                        rangeproof_len+j,
                        rangeproof_len_buf[4-j-1],
                        'i8'
                    );
                }
                var ephemeral_key = Bitcoin.bitcoin.ECPair.makeRandom();
                var secexp_buf = ephemeral_key.d.toBuffer();
                var secexp = Module._malloc(32);
                var nonce = Module._malloc(33);
                var nonce_res = Module._malloc(32);
                var pubkey_p = Module._malloc(64);
                var p_arr = Array.from(new Bitcoin.BigInteger(''+pubkey_p).toBuffer());
                while (p_arr.length < 4) p_arr.unshift(0);
                for (var j = 0; j < 32; ++j) {
                    setValue(secexp+j, secexp_buf[j], 'i8');
                }
                for (var j = 0; j < 33; ++j) {
                    setValue(nonce+j, outs[i].to_scanning_pubkey[j], 'i8');
                }
                if (1 != Module._secp256k1_ec_pubkey_parse(
                    Module.secp256k1ctx,
                    pubkey_p,
                    nonce,
                    33
                )) {
                    throw new Error('secp256k1 EC pubkey parse failed');
                }
                if (1 != Module._secp256k1_ecdh(
                    Module.secp256k1ctx,
                    nonce_res,
                    pubkey_p,
                    secexp
                )) {
                    throw new Error('secp256k1 ECDH failed');
                }
                var nonce_buf = new Bitcoin.Buffer.Buffer(32);
                for (var j = 0; j < 32; ++j) {
                    nonce_buf[j] = getValue(nonce_res + j, 'i8') & 0xff;
                }
                nonce_buf = Bitcoin.bitcoin.crypto.sha256(nonce_buf);
                for (var j = 0; j < 32; ++j) {
                    setValue(nonce_res + j, nonce_buf[j], 'i8');
                }
                if (1 != Module._secp256k1_rangeproof_sign(
                    Module.secp256k1ctx,
                    rangeproof,
                    rangeproof_len,
                    0, 0,
                    commitment,
                    getValue(blindptrs + cur_blindptr, '*'),
                    nonce_res,
                    0, 32,
                    +outs[i].value.mod(Bitcoin.BigInteger('2').pow(32)),
                    +outs[i].value.divide(Bitcoin.BigInteger('2').pow(32))
                )) {
                    throw new Error('secp256k1 rangeproof sign failed');
                }
                for (var j = 0; j < 4; ++j) {
                    rangeproof_len_buf[4-j-1] = getValue(
                        rangeproof_len+j, 'i8'
                    ) & 0xff;
                }
                len = +Bitcoin.BigInteger(rangeproof_len_buf);
                var rangeproof_buf = new Bitcoin.Buffer.Buffer(len);
                for (var j = 0; j < len; ++j) {
                    rangeproof_buf[j] = getValue(rangeproof+j, 'i8') & 0xff;
                }
                cur_blindptr += 4;
                outs[i].nonce_commitment = ephemeral_key.getPublicKeyBuffer();
                outs[i].commitment = commitment_buf;
                outs[i].range_proof = rangeproof_buf;
            }
            var tx = new Bitcoin.contrib.AlphaTransactionBuilder(cur_net);
            tx.tx.locktime = $scope.wallet.cur_block;  // nLockTime to prevent fee sniping
            for (var i = 0; i < needed_unspent.length; ++i) {
                tx.addInput(
                    needed_unspent[i].txhash,
                    needed_unspent[i].data.pt_idx,
                    0xfffffffe  // allow nLockTime to prevent fee sniping
                );
                //// tx.tx.ins[i].prevOut = needed_unspent[i].out;
                //// ^- this doesn't work (see comment below)
            }
            for (var i = 0; i < outs.length; ++i) {
                tx.addOutput(
                    Bitcoin.bitcoin.address.toBase58Check(
                        outs[i].to_hash, outs[i].to_version
                    ), 0
                )
                tx.tx.outs[i].commitment = outs[i].commitment;
                tx.tx.outs[i].range_proof = outs[i].range_proof;
                tx.tx.outs[i].nonce_commitment = outs[i].nonce_commitment;
            }
            var signatures_ds = [];
            for (var i = 0; i < needed_unspent.length; ++i) {
                (function(i) {
                    var utxo = needed_unspent[i];
                    var gawallet = new Bitcoin.bitcoin.HDNode(
                        Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(
                            new Bitcoin.Buffer.Buffer(deposit_pubkey, 'hex'),
                            cur_net
                        ),
                        new Bitcoin.Buffer.Buffer(deposit_chaincode, 'hex')
                    );
                    var gaKey;
                    if ($scope.wallet.current_subaccount) {
                        gaKey = gawallet.derive(3).then(function(branch) {
                            return branch.subpath($scope.wallet.gait_path);
                        }).then(function(gawallet) {
                            return gawallet.derive($scope.wallet.current_subaccount);
                        });
                    } else {
                        gaKey = gawallet.derive(1).then(function(branch) {
                            return branch.subpath($scope.wallet.gait_path);
                        });
                    }
                    gaKey = gaKey.then(function(gawallet) {
                        return gawallet.derive(utxo.data.pubkey_pointer);
                    });
                    var userKey = $q.when($scope.wallet.hdwallet);
                    if ($scope.wallet.current_subaccount) {
                        userKey = userKey.then(function(key) {
                            return key.deriveHardened(branches.SUBACCOUNT);
                        }).then(function(key) {
                            return key.deriveHardened($scope.wallet.current_subaccount);
                        })
                    }
                    var userKey = userKey.then(function(key) {
                        return key.derive(branches.REGULAR);
                    }).then(function(branch) {
                        return branch.derive(utxo.data.pubkey_pointer)
                    });
                    signatures_ds.push($q.all([gaKey, userKey]).then(function(keys) {
                        var gaKey = keys[0], userKey = keys[1];
                        var redeemScript = Bitcoin.bitcoin.script.multisigOutput(
                            2,
                            [gaKey.keyPair.getPublicKeyBuffer(),
                             userKey.keyPair.getPublicKeyBuffer()]
                        )
                        for (var j = 0; j < tx.tx.ins.length; ++j) {
                            // this is slightly confusing, but alphad requires
                            // all ins to serialize with the same prevout,
                            // even though this prevout is connected to only a
                            // single input
                            tx.tx.ins[j].prevOut = needed_unspent[i].out;
                        }

                        return tx.sign(i, userKey.keyPair, redeemScript, +fee);
                    }));
                })(i);
            }
            return $q.all(signatures_ds).then(function() {
                return walletsService.get_two_factor_code(
                    $scope, 'send_raw_tx'
                ).then(function(twofac_data) {
                    return tx_sender.call(
                        'http://greenaddressit.com/vault/send_raw_tx',
                        tx.build().toHex(+fee),
                        twofac_data
                    );
                });
            })
        })
    };
    walletsService.ask_for_tx_confirmation = function(
        $scope, tx, data
    ) {
        if (!($scope.send_tx || $scope.bump_fee)) {
            // not all txs support this dialog, like redepositing or sweeping
            return $q.when();
        }
        var scope = $scope.$new(), fee, value;
        if (data.response) {
            var in_value = 0, out_value = 0;
            tx.ins.forEach(function(txin) {
                var rev = new Bitcoin.Buffer.Buffer(txin.hash);
                rev = Bitcoin.bitcoin.bufferutils.reverse(rev);
                var prevtx = Bitcoin.contrib.transactionFromHex(
                    data.response.data[rev.toString('hex')]
                );
                var prevout = prevtx.outs[txin.index];
                in_value += prevout.value;
            });
            tx.outs.forEach(function(txout) {
                out_value += txout.value;
            });
            fee = in_value - out_value;
        } else {
            fee = data.fee;
        }
        if ($scope.send_tx && $scope.send_tx.amount == 'MAX') {
            value = $scope.wallet.final_balance - fee;
        } else if (data.bumped_tx) {
            value = -data.bumped_tx.value;
        } else {
            value = $scope.send_tx.amount_to_satoshis($scope.send_tx.amount);
        }
        scope.tx = {
            fee: fee,
            previous_fee: data.bumped_tx && data.bumped_tx.fee,
            value: value,
            recipient: data.recipient ? data.recipient :
                ($scope.send_tx.voucher ?
                    gettext("Voucher") :
                    ($scope.send_tx.recipient.name ||
                        $scope.send_tx.recipient))
        };
        var modal = $uibModal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_confirm_tx.html',
            scope: scope,
            windowClass: 'twofactor'  // is a 'sibling' to 2fa - show with the same z-index
        });
        return modal.result;
    }
    walletsService.sign_tx = function($scope, tx, data, prevouts, progress_cb, priv_der) {
        var prevoutToPath = function(prevout, trezor, from_subaccount) {
            var path = [];
            if (prevout.subaccount && !from_subaccount) {
                if (trezor) {
                    path.push(3 + 0x80000000);
                    path.push(prevout.subaccount + 0x80000000);
                } else {
                    path.push("3'");
                    path.push(prevout.subaccount + "'");
                }
            }
            if (priv_der) {
                if (trezor) {
                    path.push(prevout.branch + 0x80000000);
                    path.push(prevout.pointer + 0x80000000);
                } else {
                    path.push(prevout.branch + "'");
                    path.push(prevout.pointer + "'");
                }
            } else {
                path.push(prevout.branch);
                path.push(prevout.pointer);
            }
            return path;
        }
        var signatures = [], device_deferred = null, signed_n = 0;
        for (var i = 0; i < tx.ins.length; ++i) {
            (function(i) {
                var key, path = [];
                if (data.prev_outputs[i].privkey) {
                    key = $q.when(data.prev_outputs[i].privkey);
                } else if (tx_sender.hdwallet.keyPair.d) {
                    if (data.prev_outputs[i].subaccount) {
                        key = $q.when(tx_sender.hdwallet.deriveHardened(3)).then(function(key) {
                            return key.deriveHardened(data.prev_outputs[i].subaccount);
                        });
                    } else {
                        key = $q.when(tx_sender.hdwallet);
                    }
                    if (priv_der) {
                        key = key.then(function(key) {
                            return key.deriveHardened(data.prev_outputs[i].branch);
                        }).then(function(key) {
                            return key.deriveHardened(data.prev_outputs[i].pointer);
                        });
                    } else {
                        key = key.then(function(key) {
                            return key.derive(data.prev_outputs[i].branch);
                        }).then(function(key) {
                            return key.derive(data.prev_outputs[i].pointer);
                        });
                    }
                    key = key.then(function(key) {
                        return key.keyPair;
                    });
                } else {
                    path = prevoutToPath(data.prev_outputs[i]);
                }
                if (!key) {
                    // btchip or trezor -- trezor is handled separately
                    // at the end of walletsService.sign_tx
                    var script = new Bitcoin.Buffer.Buffer(data.prev_outputs[i].script, 'hex');
                    var SIGHASH_ALL = 1;
                    var sign_deferred = $q.defer();

                    if ($scope.wallet.btchip) {
                        var next = function() {
                            return $scope.wallet.btchip.gaStartUntrustedHashTransactionInput_async(
                                i == 0,
                                tx.cloneTransactionForSignature(script, i, SIGHASH_ALL),
                                i
                            ).then(function(finished) {
                                    var this_ms = 0, this_expected_ms = 6500;
                                    if ($scope.wallet.btchip.features.quickerVersion) this_expected_ms *= 0.55;
                                    var int_promise = $interval(function() {
                                        this_ms += 100;
                                        var progress = signed_n / tx.ins.length;
                                        progress += (1/tx.ins.length) * (this_ms/this_expected_ms);
                                        if (progress_cb) progress_cb(Math.min(100, Math.round(100 * progress)));
                                    }, 100);
                                    return $scope.wallet.btchip.app.gaUntrustedHashTransactionInputFinalizeFull_async(tx).then(function(finished) {
                                        return $scope.wallet.btchip.app.signTransaction_async(
                                            path.join('/'),
                                            undefined,
                                            // Cordova requires int, while crx requires ByteString:
                                            window.cordova ? tx.locktime : new ByteString(Convert.toHexInt(tx.locktime), HEX)
                                        ).then(function(sig) {
                                                $interval.cancel(int_promise);
                                                signed_n += 1;
                                                sign_deferred.resolve("30" + sig.bytes(1).toString(HEX));
                                            }, sign_deferred.reject);
                                    }, sign_deferred.reject)
                                }, sign_deferred.reject);
                        }
                        if (!device_deferred) {
                            device_deferred = next();
                        } else {
                            device_deferred = device_deferred.then(next);
                        }
                    }
                    var sign = sign_deferred.promise;
                } else {
                    var sign = key.then(function(key) {
                        signed_n += 1;
                        if (progress_cb) progress_cb(Math.round(100 * signed_n / tx.ins.length));
                        var script = new Bitcoin.Buffer.Buffer(data.prev_outputs[i].script, 'hex');
                        var SIGHASH_ALL = 1;
                        var scope = $scope.$new();
                        var in_value = 0, out_value = 0;
                        if (cur_net.isAlpha) {
                            tx.ins.forEach(function(txin) {
                                var rev = new Bitcoin.Buffer.Buffer(txin.hash);
                                rev = Bitcoin.bitcoin.bufferutils.reverse(rev);
                                var prevtx = Bitcoin.contrib.transactionFromHex(
                                    prevouts.data[rev.toString('hex')]
                                );
                                var prevout = prevtx.outs[txin.index];
                                in_value += prevout.value;
                                txin.prevValue = prevout.value;
                            });
                            tx.outs.forEach(function(txout) {
                                out_value += txout.value;
                            });
                            var fee = in_value - out_value, value;
                        }
                        if (data.prev_outputs[i].script_type == 14) {
                            var sign = $q.when(key.sign(tx.hashForSignatureV2(i, script, parseInt(data.prev_outputs[i].value), SIGHASH_ALL)));
                        } else {
                            var sign = $q.when(key.sign(tx.hashForSignature(i, script, SIGHASH_ALL)));
                        }
                        return sign.then(function(sign) {
                            var sign_serialized;
                            if (cur_net.isAlpha) {
                                sign_serialized = sign;
                            } else {
                                sign_serialized = sign.toDER();
                            }
                            sign = Bitcoin.Buffer.Buffer.concat([
                                new Bitcoin.Buffer.Buffer(sign_serialized),
                                new Bitcoin.Buffer.Buffer([SIGHASH_ALL]),
                            ]);
                            return sign.toString('hex');
                        });
                    });
                }
                signatures.push(sign);
            })(i);
        }
        if (!($scope && $scope.wallet.trezor_dev)) {
            return $q.all(signatures);
        } else {
            var fromHex = (window.trezor && trezor.ByteBuffer) ? trezor.ByteBuffer.fromHex : function (x) {
                return x;
            };
            var gawallet_hd = new Bitcoin.bitcoin.HDNode(
                Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(
                    new Bitcoin.Buffer.Buffer(deposit_pubkey, 'hex'),
                    cur_net
                ),
                new Bitcoin.Buffer.Buffer(deposit_chaincode, 'hex')
            );
            var is_2of3 = false, cur_subaccount, recovery_wallet, recovery_wallet_hd;
            for (var j = 0; j < $scope.wallet.subaccounts.length; j++) {
                if ($scope.wallet.subaccounts[j].pointer == $scope.wallet.current_subaccount &&
                    $scope.wallet.subaccounts[j].type == '2of3') {
                    is_2of3 = true;
                    cur_subaccount = $scope.wallet.subaccounts[j];
                    break;
                }
            }
            if ($scope.wallet.current_subaccount) {
                var gawallet_path = $q.when(gawallet_hd.derive(branches.SUBACCOUNT)).then(function (gawallet_hd) {
                    return gawallet_hd.subpath($scope.wallet.gait_path);
                }).then(function (subaccounts) {
                    return subaccounts.derive($scope.wallet.current_subaccount);
                });
            } else {
                var gawallet_path = $q.when(gawallet_hd.derive(branches.REGULAR)).then(function (gawallet_hd) {
                    return gawallet_hd.subpath($scope.wallet.gait_path);
                });
            }
            var hdwallet = {
                depth: 0,
                child_num: 0,
                fingerprint: 0,    // FIXME (is it important?): real fingerprint
                chain_code: fromHex($scope.wallet.hdwallet.chainCode.toString('hex')),
                public_key: fromHex($scope.wallet.hdwallet.keyPair.getPublicKeyBuffer().toString('hex'))
            };
            var path_bytes = new Bitcoin.Buffer.Buffer($scope.wallet.gait_path, 'hex'), ga_path = [];
            for (var i = 0; i < 32; i++) {
                ga_path.push(+Bitcoin.BigInteger.fromByteArrayUnsigned(path_bytes.slice(0, 2)));
                path_bytes = path_bytes.slice(2);
            }
            var script_to_hash = [];
            var change_key_bytes, recovery_wallet;
            return gawallet_path.then(function (gawallet_path_result) {
                gawallet_path = gawallet_path_result;
                gawallet = {
                    depth: 33,
                    child_num: 0,   // FIXME (is it important?): real child_num
                    fingerprint: 0,   // FIXME (is it important?): real fingerprint
                    chain_code: fromHex(gawallet_path.chainCode.toString('hex')),
                    public_key: fromHex(gawallet_path.keyPair.getPublicKeyBuffer().toString('hex'))
                };
                if ($scope.wallet.current_subaccount) {
                    return $scope.wallet.trezor_dev.getPublicKey(
                        [branches.SUBACCOUNT + 0x80000000, $scope.wallet.current_subaccount + 0x80000000]
                    ).then(function (pubkey) {
                            var pk = pubkey.message.node.public_key;
                            pk = pk.toHex ? pk.toHex() : pk;
                            var cc = pubkey.message.node.chain_code;
                            cc = cc.toHex ? cc.toHex() : cc;
                            var hd = new Bitcoin.bitcoin.HDNode(
                                Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(
                                    new Bitcoin.Buffer.Buffer(pk, 'hex'),
                                    cur_net
                                ),
                                new Bitcoin.Buffer.Buffer(cc, 'hex')
                            );

                            hdwallet = {
                                depth: 0,
                                child_num: 0,
                                fingerprint: 0,    // FIXME (is it important?): real fingerprint
                                chain_code: fromHex(hd.chainCode.toString('hex')),
                                public_key: fromHex(hd.keyPair.getPublicKeyBuffer().toString('hex'))
                            };

                            return hd.derive(1);
                        });
                } else {
                    return $scope.wallet.hdwallet.derive(1);
                }
            }).then(function (hdwallet_branch) {
                return hdwallet_branch.derive(data.change_pointer);
            }).then(function (change_key) {
                change_key_bytes = change_key.keyPair.getPublicKeyBuffer();
                return gawallet_path.derive(data.change_pointer)
            }).then(function (change_gait_key) {
                if (is_2of3) {
                    var recovery_wallet_hd = new Bitcoin.bitcoin.HDNode(
                        Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(
                            new Bitcoin.Buffer.Buffer(cur_subaccount['2of3_backup_pubkey'], 'hex'),
                            cur_net
                        ),
                        new Bitcoin.Buffer.Buffer(cur_subaccount['2of3_backup_chaincode'], 'hex')
                    );
                    recovery_wallet = {
                        depth: 0,
                        child_num: 0,
                        fingerprint: 0,    // FIXME (is it important?): real fingerprint
                        chain_code: fromHex(cur_subaccount['2of3_backup_chaincode']),
                        public_key: fromHex(cur_subaccount['2of3_backup_pubkey'])
                    };
                    return recovery_wallet_hd.derive(1).then(function (branch) {
                        return branch.derive(data.change_pointer);
                    }).then(function (change_key_recovery) {
                        return [change_gait_key.keyPair.getPublicKeyBuffer(),
                            change_key_bytes,
                            change_key_recovery.keyPair.getPublicKeyBuffer()];
                    });
                } else {
                    return [change_gait_key.keyPair.getPublicKeyBuffer(), change_key_bytes];
                }
            }).then(function (keys) {
                script_to_hash.push(Bitcoin.bitcoin.opcodes.OP_2);
                script_to_hash.push(keys[0]);
                script_to_hash.push(keys[1]);
                if (is_2of3) {
                    script_to_hash.push(keys[2]);
                    script_to_hash.push(Bitcoin.bitcoin.opcodes.OP_3);
                } else {
                    script_to_hash.push(Bitcoin.bitcoin.opcodes.OP_2);
                }
                script_to_hash.push(Bitcoin.bitcoin.opcodes.OP_CHECKMULTISIG);
                script_to_hash = Bitcoin.bitcoin.script.compile(
                    script_to_hash
                );
                var change_addr = Bitcoin.bitcoin.address.fromOutputScript(
                    Bitcoin.bitcoin.script.scriptHashOutput(
                        Bitcoin.bitcoin.crypto.hash160(script_to_hash)
                    ),
                    cur_net
                );
                var get_pubkeys = function (prevout, is2of3) {
                    var ret = [{
                        node: gawallet,
                        address_n: [prevout.pointer]
                    },
                        {
                            node: hdwallet,
                            address_n: prevoutToPath(prevout, true, $scope.wallet.current_subaccount)
                        }];
                    if (is2of3) {
                        ret.push({
                            node: recovery_wallet,
                            address_n: prevoutToPath(prevout, true, true)
                        });
                    }
                    return ret;
                }
                var inputs = [];
                for (var i = 0; i < tx.ins.length; ++i) {
                    inputs.push({
                        address_n: prevoutToPath(data.prev_outputs[i], true),
                        prev_hash: fromHex(
                            Bitcoin.bitcoin.bufferutils.reverse(
                                tx.ins[i].hash
                            ).toString('hex')
                        ),
                        prev_index: tx.ins[i].index,
                        script_type: (window.trezor && trezor.ByteBuffer) ? 1 : 'SPENDMULTISIG',
                        multisig: {
                            pubkeys: get_pubkeys(data.prev_outputs[i], is_2of3),
                            m: 2
                        },
                        sequence: tx.ins[i].sequence
                    })
                }

                var convert_ins = function (ins) {
                    return ins.map(function (inp) {
                        var fromHex = (window.trezor && trezor.ByteBuffer) ? trezor.ByteBuffer.fromHex : function (x) {
                            return x;
                        };
                        return {
                            prev_hash: fromHex(
                                Bitcoin.bitcoin.bufferutils.reverse(
                                    inp.hash
                                ).toString('hex')
                            ),
                            prev_index: inp.index,
                            script_sig: fromHex(inp.script.toString('hex')),
                            sequence: inp.sequence
                        }
                    })
                }
                var convert_outs = function (outs) {
                    return outs.map(function (out) {
                        var TYPE_ADDR = (window.trezor && trezor.ByteBuffer) ? 0 : 'PAYTOADDRESS';
                        var TYPE_P2SH = (window.trezor && trezor.ByteBuffer) ? 1 : 'PAYTOSCRIPTHASH';
                        var TYPE_MULTISIG = (window.trezor && trezor.ByteBuffer) ? 2 : 'PAYTOMULTISIG';
                        var addr = Bitcoin.bitcoin.address.fromOutputScript(
                            out.script, cur_net
                        );
                        var ret = {
                            amount: out.value,
                            address: addr,
                            script_type: Bitcoin.bitcoin.script.isScriptHashOutput(
                                out.script
                            ) ? TYPE_P2SH : TYPE_ADDR
                        };
                        if (ret.address == change_addr) {
                            ret.script_type = TYPE_MULTISIG;
                            ret.multisig = {
                                pubkeys: get_pubkeys({
                                    branch: 1,
                                    pointer: data.change_pointer
                                }, is_2of3),
                                m: 2
                            }
                        } else if (data.out_pointers && data.out_pointers.length == 1) {
                            // FIXME: perhaps at some point implement the case of 'single redeposit transaction',
                            // which is a bit complicated because different outputs can be from different
                            // subaccounts
                            ret.script_type = TYPE_MULTISIG;
                            ret.multisig = {
                                pubkeys: get_pubkeys({
                                    branch: 1,
                                    pointer: data.out_pointers[0].pointer
                                }, is_2of3),
                                m: 2
                            }
                        }
                        return ret;
                    })
                }
                var convert_outs_bin = function (outs) {
                    return outs.map(function (out) {
                        var fromHex = (window.trezor && trezor.ByteBuffer) ? trezor.ByteBuffer.fromHex : function (x) {
                            return x;
                        };
                        return {
                            amount: out.value,
                            script_pubkey: fromHex(out.script.toString('hex'))
                        };
                    })
                }

                var txs = [];

                for (var k in prevouts.data) {
                    var parsed = Bitcoin.bitcoin.Transaction.fromHex(prevouts.data[k]);
                    txs.push({
                        hash: k.toString('hex'),
                        version: parsed.version,
                        lock_time: parsed.locktime,
                        bin_outputs: convert_outs_bin(parsed.outs),
                        inputs: convert_ins(parsed.ins)
                    });
                }
                return $scope.wallet.trezor_dev.signTx(inputs, convert_outs(tx.outs),
                    txs, {
                        coin_name: cur_net == Bitcoin.bitcoin.networks.bitcoin
                            ? 'Bitcoin' : 'Testnet'
                    }).then(function (res) {
                        return res.message.serialized.signatures.map(function (a) {
                            return (a.toHex ? a.toHex() : a) + "01";
                        });
                    });

            });
        }
    }
    walletsService.sign_and_send_tx = function($scope, data, priv_der, twofactor, notify, progress_cb, send_after) {
        var d = $q.defer();
        var tx = Bitcoin.contrib.transactionFromHex(data.tx);
        var prevouts_d;
        var response;
        if ($scope && ($scope.send_tx || $scope.wallet.trezor_dev)) {
            prevouts_d = $http.get(data.prevout_rawtxs).then(function(response_) {
                response = response_;
                return response;
            });
        } else {
            prevouts_d = $q.when();
        }
        var d_all = prevouts_d.then(function(prevouts) {
            return walletsService.sign_tx($scope, tx, data, prevouts, progress_cb, priv_der);
        })
        if (!send_after) {
            send_after = $q.when();
        }
        d_all = d_all.then(function(signatures) {
            return walletsService.ask_for_tx_confirmation(
                $scope, tx, {response: response}
            ).then(function() {
                    return signatures;
                });
        }, d.reject);
        var do_send = function() {
            return d_all.then(function(signatures) {
                if (!twofactor && data.requires_2factor) {
                    return walletsService.get_two_factor_code($scope, 'send_tx').then(function(twofac_data) {
                        return [signatures, twofac_data];
                    });
                } else {
                    return [signatures, twofactor];
                }
            }).then(function(signatures_twofactor) {
                var signatures = signatures_twofactor[0], twofactor = signatures_twofactor[1];
                tx_sender.call("http://greenaddressit.com/vault/send_tx", signatures, twofactor||null).then(function(data) {
                    d.resolve();
                    if (!twofactor && $scope) {
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
                    notices.makeNotice('error', gettext('Transaction failed: ') + reason.args[1]);
                    sound.play(BASE_URL + "/static/sound/wentwrong.mp3", $scope);
                });
            }, d.reject);
        }
        send_after.then(do_send, d.reject);
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
    walletsService.get_two_factor_code = function($scope, action, data, redeposit) {
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
                }
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
                            notices.makeNotice('error', err.args[1]);
                            that.requesting_code = false;
                        });
                    }};
                var show_modal = function() {
                    var modal = $uibModal.open({
                        templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_2fa.html',
                        scope: $scope,
                        windowClass: 'twofactor'
                    });
                    modal.opened.then(function() { focus("twoFactorModal"); });
                    deferred.resolve(modal.result.then(function(twofac_data) {
                        if (twofac_data.method == 'gauth' && redeposit) {
                            return tx_sender.call('http://greenaddressit.com/twofactor/request_redeposit_proxy', twofac_data).then(function(data) {
                                return {'method': 'proxy', 'code': data};
                            });
                        } else {
                            return twofac_data;
                        }
                    }));
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
    walletsService.addCurrencyConversion = function($scope, model_name) {
        var div = {'BTC': 1, 'mBTC': 1000, 'µBTC': 1000000, 'bits':1000000}[$scope.wallet.unit];
        var unitPlaces = {'BTC': 8, 'mBTC': 5, 'µBTC': 2, 'bits': 2}[$scope.wallet.unit];
        var trimDecimalPlaces = function(numPlaces, val) {
            return (Math.round(val * Math.pow(10, numPlaces)) / Math.pow(10, numPlaces));
        }
        $scope.$watch(model_name+'.amount', function(newValue, oldValue) {
            // don't check for newValue == oldValue to allow conversion to happen
            // in 'send' form even when using plain (non-payreq) bitcoin: URI with amount
            var _update = function() {
                if ($scope[model_name].updated_by_conversion) {
                    $scope[model_name].updated_by_conversion = false;
                } else {
                    var oldFiat = $scope[model_name].amount_fiat;
                    if (!newValue) {
                        $scope[model_name].amount_fiat = undefined;
                    } else {
                        if (newValue == 'MAX') {
                            $scope[model_name].amount_fiat = 'MAX';
                        } else {
                            $scope[model_name].amount_fiat = newValue * $scope.wallet.fiat_rate / div;
                            $scope[model_name].amount_fiat = trimDecimalPlaces(2, $scope[model_name].amount_fiat);
                        }
                    }
                    if ($scope[model_name].amount_fiat !== oldFiat) {
                        $scope[model_name].updated_by_conversion = true;
                    }
                }
            }
            if ($scope.wallet.fiat_rate) {
                _update();
            } else {
                $scope.$on('first_balance_updated', _update);
            }
        });
        $scope.$watch(model_name+'.amount_fiat', function(newValue, oldValue) {
            if (newValue === oldValue) return;
            var _update = function() {
                if ($scope[model_name].updated_by_conversion) {
                    $scope[model_name].updated_by_conversion = false;
                } else {
                    var oldBTC = $scope[model_name].amount;
                    if (!newValue) {
                        $scope[model_name].amount = undefined;
                    } else {
                        if (newValue == 'MAX') {
                            $scope[model_name].amount = 'MAX';
                        } else {
                            $scope[model_name].amount = (div * newValue / $scope.wallet.fiat_rate);
                            $scope[model_name].amount = trimDecimalPlaces(unitPlaces, $scope[model_name].amount);
                        }
                    }
                    if ($scope[model_name].amount !== oldBTC) {
                        $scope[model_name].updated_by_conversion = true;
                    }
                }
            }
            if ($scope.wallet.fiat_rate) {
                _update();
            } else {
                $scope.$on('first_balance_updated', _update);
            }
        });
    };
    walletsService.set_last_fiat_update = function($scope) {
        $timeout(function(){
            var now = 1*((new Date()).getTime()/1000).toFixed()
            var diff = $scope.wallet.fiat_last_fetch_ss = $scope.wallet.fiat_last_fetch ? (now - $scope.wallet.fiat_last_fetch) : 0;
            $scope.wallet.fiat_lastupdate_mm = (diff > 60) ? Math.floor(diff / 60) : 0;
            $scope.wallet.fiat_lastupdate_ss = (diff % 60);
            walletsService.set_last_fiat_update($scope);
        }, 1000)
    };
    walletsService.create_pin = function(pin, $scope, suffix) {
        suffix = suffix || '';
        var do_create = function() {
            var deferred = $q.defer();
            tx_sender.call('http://greenaddressit.com/pin/set_pin_login', pin, 'Primary').then(
                function(data) {
                    if (data) {
                        var pin_ident = tx_sender['pin_ident'+suffix] = data;
                        storage.set('pin_ident'+suffix, pin_ident);
                        storage.set(
                            'pin_chaincode'+suffix,
                            $scope.wallet.hdwallet.chainCode.toString('hex')
                        );
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
                                        storage.set('encrypted_seed'+suffix, encrypted);
                                        if (!suffix) {
                                            // chaincode is not used for Touch ID
                                            storage.set('pin_chaincode', data)
                                        }
                                    });
                                    tx_sender.pin = pin;
                                    deferred.resolve(pin_ident);
                                } else {
                                    deferred.reject(gettext('Failed retrieving password.'))
                                }
                            }, function(err) {
                                deferred.reject(err.args[1]);
                            });
                    } else {
                        deferred.reject();
                    }
                }, function(err) {
                    deferred.reject(err.args[1]);
                }
            );
            return deferred.promise;
        };
        if (!tx_sender.logged_in) {
            return $q.when(Bitcoin.bitcoin.HDNode.fromSeedHex($scope.wallet.hdwallet.seed_hex, cur_net)).then(function(hdwallet) {
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
        return $uibModal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_logout.html',
            scope: $scope
        }).result;
    };
    return walletsService;
}]).factory('notices', ['$rootScope', '$timeout', function($rootScope, $timeout) {
    var notices = $rootScope.notices = [];
    var noticesService = {};
    noticesService.makeError = makeError;
    noticesService.makeNotice = makeNotice;
    noticesService.setLoadingText = setLoadingText;

    var errorMessages = {
        notenoughmoney: gettext("Not enough money, you need ${missing_satoshis} more ${unit} to cover the transaction and fee")
    };

    return noticesService;

    function makeError ($scope, error) {
        // this is the error object directly from an API call
        if (error.error !== 'com.greenaddress.error') {
            console.warn('Non-greenaddress error passed to makeError');
            return noticesService.makeNotice('error', error.message || error.msg || error);
        }
        var code = getErrorCode(error);
        var message = error.args[1];
        var args = parseArgs(error.args[2] || {});

        if (code in errorMessages) {
            message = errorMessages[code];
        }
        message = decorateError(message, args);

        return noticesService.makeNotice('error', message);

        // we want the scope
        function parseArgs (args) {
            var div = {'BTC': 1, 'mBTC': 1000, 'µBTC': 1000000, 'bits':1000000};
            args.unit = $scope.wallet.unit;

            // special parsing rules
            if (args.missing_satoshis) {
                args.missing_satoshis = Math.round(args.missing_satoshis * div[$scope.wallet.unit]) / 100000000;
            }
            return args;
        }
    }
    function decorateError (message, args) {
        Object.keys(args).forEach(function (argName) {
            message = message.replace('${' + argName + '}', args[argName]);
        });
        return message;
    }
    function getErrorCode (error) {
        return error.args[0].substr(error.args[0].indexOf('#')+1);
    }

    function makeNotice (type, msg, timeout) {
        if (msg == null || msg.length == 0)
            return;

        console.log(msg);
        var is_chrome_app = window.chrome && chrome.storage;
        if (is_chrome_app) {
            var opt = {
                type: "basic",
                title: "GreenAddress Notification",
                message: msg,
                iconUrl: BASE_URL + "/static/img/logos/logo-greenaddress.png"
            };

            chrome.notifications.create("", opt);
        }

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
    }
    function setLoadingText (text, ifNotSet) {
        if (!ifNotSet || !$rootScope.loading_text) {
            $rootScope.loading_text = text;
        }
    }

}]).factory('tx_sender', ['$q', '$rootScope', 'cordovaReady', '$http', 'notices', 'gaEvent', '$location', 'autotimeout', 'device_id', 'btchip',
        function($q, $rootScope, cordovaReady, $http, notices, gaEvent, $location, autotimeout, device_id, btchip) {
    var txSenderService = {};
    // disable electrum setup
    if (false && window.Electrum) {
        if (window.cordova) {
            txSenderService.electrum = new Electrum($http, $q);
        } else {
            txSenderService.electrum = new Electrum();
            txSenderService.electrum.connectToServer();
        }
    }
    var connection, session, session_for_login, calls = [], calls_missed = {}, calls_counter = 0, global_login_d;
    var onLogin = function(data) {
        var s = session || session_for_login;
        s.subscribe('com.greenaddress.txs.wallet_' + data.receiving_id,
                function(event) {
            gaEvent('Wallet', 'TransactionNotification');
            $rootScope.$broadcast('transaction', event[0]);
        });
        s.subscribe('com.greenaddress.fee_estimates',
                function(event) {
            $rootScope.$broadcast('fee_estimate', event[0]);
        });
    };
    txSenderService.call = function() {
        var d = $q.defer();
        if (session) {
            var cur_call = calls_counter++;
            calls_missed[cur_call] = [arguments, d];  // will be called on new session
            try {
                var uri = arguments[0].replace('http://greenaddressit.com/', 'com.greenaddress.').replace('/', '.');
                session.call.apply(session, [uri, Array.prototype.slice.call(arguments, 1)]).then(function(data) {
                    if (!calls_missed[cur_call]) return;  // avoid resolving the same call twice
                    delete calls_missed[cur_call];
                    d.resolve(data);
                }, function(err) {
                    if (err.args[0] == 'http://greenaddressit.com/error#internal' && err.args[1] == 'Authentication required') {
                        return; // keep in missed calls queue for after login
                    }
                    if (err.args[0] == 'http://greenaddressit.com/error#sessionexpired') {
                        d.reject({args: [
                            err.args[0],
                            gettext("Session expired. Please try again.")
                        ]});
                        connection.close();
                        connection = session = session_for_login = null;
                        connecting = false;
                        connect(global_login_d);
                        return;
                    }
                    if (!calls_missed[cur_call]) return;  // avoid resolving the same call twice
                    delete calls_missed[cur_call];
                    d.reject(err);
                });
                var args = arguments, timeout;
                if (args[0] == "com.greenaddress.vault.prepare_sweep_social") timeout = 40000;
                else timeout = 10000;
                setTimeout(function() {
                    delete calls_missed[cur_call];
                    $rootScope.safeApply(function() {
                        d.reject({desc:
                            gettext('Request timed out (%s)')
                                .replace('%s', args[0].split('/').slice(3).join('/'))
                        });
                    });
                }, timeout);
            } catch (e) {
                //if (!calls_missed[cur_call]) return;  // avoid resolving the same call twice
                delete calls_missed[cur_call];
                d.reject(gettext('Problem with connection detected. Please try again.'));
            }
        } else {
            if (disconnected) {
                disconnected = false;
                connect(global_login_d);
            }
            calls.push([arguments, d]);
        }
        return d.promise;
    };
    var isMobile = /Android|iPhone|iPad|iPod|Opera Mini/i.test(navigator.userAgent);
    if (window.cordova) {
        cordovaReady(function() {
            document.addEventListener("resume", function() {
                if (!txSenderService.wallet || !txSenderService.logged_in) return;
                if (session || session_for_login) {
                    connection.close();  // reconnect on resume
                }
                session = session_for_login = null;
                disconnected = true;
                txSenderService.wallet.update_balance();
            }, false);
        })();
    } else if (isMobile && typeof document.addEventListener !== undefined) {
        // reconnect on tab shown in mobile browsers
        document.addEventListener("visibilitychange", function() {
            if (!document.hidden && txSenderService.wallet && txSenderService.logged_in) {
                txSenderService.wallet.update_balance();
            }
        }, false);
    }
    var attempt_login = false;
    var onAuthed = function(s, login_d) {
        session_for_login = s;
        session_for_login.subscribe('com.greenaddress.blocks', function(event) {
            $rootScope.$broadcast('block', event[0]);
        });
        var d, logging_in = false;
        if (txSenderService.hdwallet && (txSenderService.logged_in || attempt_login)) {
            d = txSenderService.login('if_same_device', true); // logout=if_same_device, force_relogin
            logging_in = true;
        } else if (txSenderService.watch_only) {
            d = txSenderService.loginWatchOnly(txSenderService.watch_only[0], txSenderService.watch_only[1]);
            logging_in = true;
        } else {
            d = $q.when(true);
        }
        d.catch(function(err) {
            if (err.uri == 'http://greenaddressit.com/error#doublelogin') {
                if (login_d) {
                    // login_d handler may want to handle double login by forcing logout
                    login_d.reject(err);
                    return;
                }
                autotimeout.stop();
                if (txSenderService.wallet) txSenderService.wallet.clear();
                $location.path('/concurrent_login');
            } else {
                console.log(err);
                notices.makeNotice('error', gettext('An error has occured which forced us to log you out.'))
                if (txSenderService.wallet) txSenderService.wallet.clear();
                $location.path('/');
            }
        });
        d.then(function(result) {
            session = session_for_login;
            if (logging_in && login_d) {
                login_d.resolve(result);
            }
            // missed calls queues
            for (i in calls_missed) {
                var item = calls_missed[i];
                delete calls_missed[i];
                item[1].resolve(txSenderService.call.apply(session, item[0]));
            }
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
    var disconnected = false, connecting = false, nconn = 0;
    var connect = function(login_d) {
        global_login_d = login_d;
        if (connecting) return;
        connecting = true;
        nconn += 1;
        var retries = 60, everConnected = false;
        (function (nc) {
            connection = new autobahn.Connection({
                url: wss_url,
                realm: "realm1",
                use_deferred: $q.defer
            });
            connection.onclose = function() {
                session = session_for_login = null;
                disconnected = true;
            }
            connection.onopen =
                function(s) {
                    s.caller_disclose_me = true;
                    everConnected = true;
                    if (nc != nconn) {
                        // newer connection created - close the old one
                        s.close();
                        return;
                    }
                    s.nc = nc;
                    connecting = false;
                    global_login_d = undefined;
                    onAuthed(s, login_d, nc);
                }; /*,
                function(code, reason) {
                    if (retries && !everConnected) {  // autobahnjs doesn't reconnect automatically if it never managed to connect
                        retries -= 1;
                        setTimeout(function() { connecting = false; connect(login_d); }, 5000);
                        return;
                    }
                    if (reason && reason.indexOf('WS-4000') != -1) {
                        $rootScope.$apply(function() {
                            autotimeout.stop();
                            txSenderService.logout();
                            $location.path('/concurrent_login');
                        });
                    }
                    if (reason && reason.indexOf('WS-4001') != -1 &&  // concurrent login on the same device
                            nc == nconn) {  // allow concurrent logins in the same session in case of service restarts
                        $rootScope.$apply(function() {
                            autotimeout.stop();
                            txSenderService.logout();
                            $location.path('/');
                        });
                    }
                    if (nc == nconn) {
                        session = session_for_login = null;
                        disconnected = true;
                        connecting = false;
                        global_login_d = undefined;
                    }
                },
                {maxRetries: 60}
            ); */

            connection.open();
        })(nconn);
    };
    cordovaReady(connect)();
    txSenderService.logged_in = false;
    var waiting_for_device = false;
    txSenderService.login = function(logout, force_relogin, user_agent) {
        var d_main = $q.defer();
        if (txSenderService.logged_in && !force_relogin) {
            d_main.resolve(txSenderService.logged_in);
        } else {
            var hdwallet = txSenderService.hdwallet;
            attempt_login = true;
            if (hdwallet.keyPair.d) {
                if (session_for_login) {
                    session_for_login.call('com.greenaddress.login.get_challenge',
                            [hdwallet.getAddress().toString()]).then(function(challenge) {

                        var challenge_bytes = new Bitcoin.BigInteger(challenge).toBuffer();

                        // generate random path to derive key from - avoids signing using the same key twice
                        var random_path_hex = new Bitcoin.BigInteger.fromBuffer(
                            Bitcoin.randombytes(8)
                        ).toString(16);
                        while (random_path_hex.length < 16) random_path_hex = '0' + random_path_hex;
                        $q.when(hdwallet.subpath_for_login(random_path_hex)).then(function(subhd) {
                            $q.when(subhd.keyPair.sign(challenge_bytes)).then(function(signature) {
                                d_main.resolve(device_id().then(function(devid) {
                                    if (session_for_login && session_for_login.nc == nconn) {
                                        if (!cur_net.isAlpha) {
                                            signature = [signature.r.toString(), signature.s.toString()];
                                        }
                                        return session_for_login.call('com.greenaddress.login.authenticate',
                                                [signature, logout||false,
                                                 random_path_hex, devid, user_agent]).then(function(data) {
                                            if (data) {
                                                txSenderService.logged_in = data;
                                                onLogin(data);
                                                return data;
                                            } else { return $q.reject(gettext('Login failed')); }
                                        });
                                    } else if (!connecting) {
                                        disconnected = false;
                                        d = $q.defer();
                                        connect(d);
                                        d_main.resolve(d.promise);
                                    }
                                }));
                            });
                        });
                    });
                } else if (!connecting) {
                    disconnected = false;
                    d = $q.defer();
                    connect(d);
                    d_main.resolve(d.promise);
                }
            } else {  // trezor_dev || btchip
                if (waiting_for_device) return;
                var trezor_dev = txSenderService.trezor_dev,
                    btchip_dev = txSenderService.btchip;
                var get_pubkey = function() {
                    if (trezor_dev) {
                        return $q.when(txSenderService.trezor_address);
                    } else {
                        return $q.when(txSenderService.btchip_address);
                    }
                }
                get_pubkey().then(function (addr) {
                    if (session_for_login) {
                        if (trezor_dev) {
                            dev_d = $q.when(trezor_dev);
                        } else {
                            dev_d = btchip.getDevice(false, true,
                                    // FIXME not sure why it doesn't work with Cordova
                                    // ("suspend app, disconnect dongle, resume app, reconnect dongle" case fails)
                                    window.cordova ? null : btchip_dev).then(function(btchip_dev_) {
                                txSenderService.btchip = btchip_dev = btchip_dev_;
                            });
                        }
                        waiting_for_device = true;
                        var challenge_arg_resolves_main = false;
                        dev_d = dev_d.then(function() {
                            if (session_for_login) {
                                return session_for_login.call(
                                    'com.greenaddress.login.get_trezor_challenge',
                                    [addr, !trezor_dev]
                                );
                            } else if (!connecting) {
                                waiting_for_device = false;
                                disconnected = false;
                                d = $q.defer();
                                connect(d);
                                challenge_arg_resolves_main = true;
                                return d.promise;
                            } else waiting_for_device = false;
                        });
                        d_main.resolve(dev_d.then(function(challenge) {
                            if (challenge_arg_resolves_main) return challenge;
                            if (!challenge) return $q.defer().promise;  // never resolve

                            var msg_plain = 'greenaddress.it      login ' + challenge;
                            var msg = (new Bitcoin.Buffer.Buffer(
                                msg_plain, 'utf8'
                            )).toString('hex');
                            // btchip requires 0xB11E to skip HID authentication
                            // 0x4741 = 18241 = 256*G + A in ASCII
                            var path = [0x4741b11e];

                            if (trezor_dev) {
                                trezor_dev.signing = true;
                                return trezor_dev._typedCommonCall('SignMessage', 'MessageSignature',
                                        {'message': msg, address_n: path}).then(function(res) {
                                    var sig = res.message.signature;
                                    sig = sig.toHex ? sig.toHex() : sig;
                                    var signature = Bitcoin.bitcoin.ECSignature.parseCompact(
                                        new Bitcoin.Buffer.Buffer(sig, 'hex')
                                    );
                                    trezor_dev.signing = false;
                                    return device_id().then(function(devid) {
                                        return session_for_login.call('com.greenaddress.login.authenticate',
                                                [[signature.signature.r.toString(), signature.signature.s.toString(), signature.i.toString()], logout||false,
                                                 'GA', devid]).then(function(data) {
                                            if (data) {
                                                txSenderService.logged_in = data;
                                                onLogin(data);
                                                return data;
                                            } else { return $q.reject(gettext('Login failed')); }
                                        });
                                    });
                                }, function(err) {
                                    trezor_dev.signing = false;
                                    return $q.reject(err.message);
                                });
                            } else {
                                var t0 = new Date();
                                return $q.when(hdwallet.derive(path[0])).then(function(result_pk) {
                                    return btchip_dev.signMessagePrepare_async(path.join('/'), new ByteString(msg, HEX)).then(function(result) {
                                        return btchip_dev.app.signMessageSign_async(new ByteString("00", HEX)).then(function(result) {
                                            waiting_for_device = false;
                                            var signature = Bitcoin.bitcoin.ECSignature.fromDER(
                                                new Bitcoin.Buffer.Buffer("30" + result.bytes(1).toString(HEX), 'hex')
                                            );
                                            if (btchip_dev.features.signMessageRecoveryParam) {
                                                var i = result.byteAt(0) & 0x01;
                                            } else {
                                                var i = Bitcoin.ecdsa.calcPubKeyRecoveryParam(
                                                    Bitcoin.BigInteger.fromBuffer(Bitcoin.message.magicHash(msg_plain)),
                                                    {r: signature.r, s: signature.s},
                                                    result_pk.keyPair.Q
                                                )
                                            }
                                            return device_id().then(function(devid) {
                                                if (session_for_login && session_for_login.nc == nconn) {
                                                    return session_for_login.call('com.greenaddress.login.authenticate',
                                                            [[signature.r.toString(), signature.s.toString(), i.toString()], logout||false,
                                                             'GA', devid]).then(function(data) {
                                                        if (data) {
                                                            txSenderService.logged_in = data;
                                                            onLogin(data);
                                                            return data;
                                                        } else { return $q.reject(gettext('Login failed')); }
                                                    });
                                                } else if (!connecting) {
                                                    disconnected = false;
                                                    d = $q.defer();
                                                    connect(d);
                                                    return d.promise;
                                                }
                                            });
                                        });
                                    });
                                });
                            }
                        }).finally(function() { waiting_for_device = false; }));
                    } else if (!connecting) {
                        disconnected = false;
                        d = $q.defer();
                        connect(d);
                        d_main.resolve(d.promise);
                    }
                });
            }
        }
        return d_main.promise;
    };
    txSenderService.logout = function() {
        if (session) {
            connection.close();
            session = session_lor_login = null;
            disconnected = true;
        }
        for (var key in calls_missed) {
            delete calls_missed[key];
        }
        if (txSenderService.btchip) {
            txSenderService.btchip.dongle.disconnect_async();
        }
        disconnected = true;
        txSenderService.logged_in = false;
        attempt_login = false;
        txSenderService.hdwallet = undefined;
        txSenderService.trezor_dev = undefined;
        txSenderService.watch_only = undefined;
        txSenderService.pin_ident = undefined;
        txSenderService.has_pin = undefined;
        if (txSenderService.wallet) txSenderService.wallet.clear();
    };
    txSenderService.loginWatchOnly = function(token_type, token, logout) {
        var d = $q.defer();
        txSenderService.call('http://greenaddressit.com/login/watch_only',
            token_type, token, logout||false).then(function(data) {
                txSenderService.watch_only = [token_type, token];
                onLogin(data);
                d.resolve(data);
            }, function(err) {
                d.reject(err);
            });
        return d.promise;
    };
    txSenderService.change_pin = function(new_pin) {
        return txSenderService.call('http://greenaddressit.com/pin/change_pin_login',
                new_pin, txSenderService.pin_ident).then(function(res) {
            // keep new pin for reconnection handling
            if (!res) {
                return $q.reject(gettext('Changing PIN failed.'));
            } else {
                txSenderService.pin = new_pin;
            }
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
        if (uri.indexOf === undefined || uri.indexOf("bitcoin:") == -1) {
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
                    var key_arr;
                    if (key.constructor == Array) {
                        key_arr = key;
                    } else {
                        key_arr = [key];
                    }
                    // make it compatible with localStorage.getItem:
                    // (returns null if key is missing)
                    for (var i = 0; i < key_arr.length; ++i) {
                        if (items[key_arr[i]] === undefined) {
                            items[key_arr[i]] = null;
                        }
                    }
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
}]).factory('user_agent', [function() {
    var is_chrome_app = window.chrome && chrome.storage,
        is_cordova_app = window.cordova;
    return function(wallet) {
        if (is_cordova_app) {
            return 'Cordova ' + cordova.platformId +
                ' (version=' + wallet.version + ')';
        } else if (is_chrome_app) {
            return 'Chrome ' + '(version=' + wallet.version + ')';
        } else {
            return 'Browser';
        }
    };
}]).factory('addressbook', ['$rootScope', 'tx_sender', 'storage', 'crypto', 'notices', '$q',
        function($rootScope, tx_sender, storage, crypto, notices, $q) {
    var PER_PAGE = 15;
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
            if (value.name) return value;
            if (value[3] == 'facebook') {
                var has_wallet = value[4];
                if (!has_wallet && (is_chrome_app || window.cordova)) return;  // can't send FB messages from Chrome/Cordova app
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
                if (value[0] === $routeParams.name) $routeParams.page = Math.ceil((i+1)/PER_PAGE);
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
                var subaccounts = [];
                // start with i = 1 - do not show 'Main' in the addressbook
                for (var i = 1; i < $scope.wallet.subaccounts.length; i++) {
                    var account = $scope.wallet.subaccounts[i];
                    subaccounts.push([account.name, account.receiving_id, '', 'subaccount', true]);
                }
                if (cache.hashed) {
                    d = crypto.decrypt(cache.items, $scope.wallet.cache_password).then(function(decrypted) {
                        that.update_with_items(JSON.parse(decrypted).concat(subaccounts), $routeParams);
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
                            that.update_with_items(items.concat(subaccounts), $routeParams);
                        }
                    }, function(err) {
                        notices.makeNotice('error', gettext('Error reading address book: ') + err.args[1]);
                    }).finally(function() {
                        if (requires_load) {
                            $rootScope.decrementLoading();
                        }
                    });
                });
            });
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
                if (!$scope || !$scope.wallet.appearance.sound) {
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

}]).factory('qrcode', ['$q', 'cordovaReady', '$timeout', function($q, cordovaReady, $timeout) {
    var n = navigator, v, webkit = false, moz = false, gCtx, stream, gotGUMerror = false;
    return {
    stop_scanning: function($scope) {
        $scope.scanning_qr_video = false;
        v.pause();
        try {
            stream.stop();
        } catch (e) {
            stream.getVideoTracks()[0].stop();
        }
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
                              $timeout(function() { deferred.resolve(result.text); });
                        } else {
                            if (result.cancelled) {
                                $timeout(function() { deferred.reject(gettext('Cancelled')); });
                            } else {
                                $timeout(function() { deferred.reject(gettext('Invalid format')); });
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

                    var canvas = document.getElementById("qr-canvas");
                    if (!canvas) {
                        canvas = document.createElement('canvas');
                    }
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
}]).factory('hw_detector', ['$q', 'trezor', 'btchip', '$timeout', '$rootScope', '$uibModal',
        function($q, trezor, btchip, $timeout, $rootScope, $uibModal) {
    return {
        success: false,
        showModal: function(d) {
            var that = this;
            if (!that.modal) {
                $rootScope.safeApply(function() {
                    var options = {
                        templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_usb_device.html',
                    };
                    that.modal = $uibModal.open(options);
                    that.modal.result.finally(function() {
                        if (!that.success) d.reject();
                    });
                });
            };
        },
        waitForHwWallet: function() {
            var d = $q.defer(), that = this;
            var doSuccess = function() {
                d.resolve();
                that.success = true;
                if (that.modal) {
                    that.modal.close();  // modal close cancels the tick
                }
            }
            var check = function() {
                trezor.getDevice(true).then(function() {
                    doSuccess();
                }, function(err) {
                    if (err && (err.pluginLoadFailed || err.outdatedFirmware)) {
                        // don't retry on unrecoverable errors
                        d.reject();
                        return;
                    }
                    btchip.getDevice(true).then(function() {
                        doSuccess();
                    }, function() {
                        // can be set to success by signup (if trezor got connected)
                        if (!that.success) that.showModal(d);
                        $timeout(check, 1000);
                    });
                })
            }
            check();
            return d.promise;
        }
    }
}]).factory('trezor', ['$q', '$interval', '$uibModal', 'notices', '$rootScope', 'focus',
        function($q, $interval, $uibModal, notices, $rootScope, focus) {

    var trezor_api, transport, trezor;

    var promptPin = function(type, callback) {
        var scope, modal;
        scope = angular.extend($rootScope.$new(), {
            pin: '',
            type: type
        });

        modal = $uibModal.open({
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

    var promptPassphrase = function(callback) {
        var scope, modal;

        scope = angular.extend($rootScope.$new(), {
            passphrase: '',
        });

        modal = $uibModal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_trezor_passphrase.html',
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

    var handleError = function(e) {
        var message;
        if (e == 'Opening device failed') {
            message = gettext("Device could not be opened. Make sure you don't have any TREZOR client running in another tab or browser window!");
        } else {
            message = e;
        }
        $rootScope.safeApply(function() {
            notices.makeNotice('error', message);
        });
    };

    var handleButton = function(dev) {
        var modal = $uibModal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_trezor_confirm_button.html',
            size: 'sm',
            windowClass: 'pinmodal',
            backdrop: 'static',
            keyboard: false
        });

        dev.once('pin', function () {
            try { modal.close(); } catch (e) {}
        });
        dev.once('receive', function () {
            try { modal.close(); } catch (e) {}
        });
        dev.once('error', function () {
            try { modal.close(); } catch (e) {}
        });
    }

    return {
        getDevice: function(noModal, silentFailure) {
            var deferred = $q.defer();
            var is_chrome_app = window.chrome && chrome.storage;
            if (!is_chrome_app) return deferred.promise;

            var tick, modal;
            var showModal = function() {
                if (!noModal && !modal) {
                    modal = $uibModal.open({
                        templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_usb_device.html',
                    });
                    modal.result.finally(function() {
                        if (tick) {
                            $interval.cancel(tick);
                        }
                    });
                }
            }

            if (trezor_api) {
                var plugin_d = $q.when(trezor_api);
            } else {
                var plugin_d = window.trezor.load();
            }
            plugin_d.then(function(api) {
                trezor_api = api;
                tick = $interval(function() {
                    var enumerate_fun = is_chrome_app ? 'devices' : 'enumerate';
                    $q.when(trezor_api[enumerate_fun]()).then(function(devices) {
                        if (devices.length) {
                            if (noModal) {
                                $interval.cancel(tick);
                            } else if (modal) {
                                modal.close();  // modal close cancels the tick
                            } else {
                                $interval.cancel(tick);
                            }
                            var acquire_fun = is_chrome_app ? 'open' : 'acquire';
                            $q.when(trezor_api[acquire_fun](devices[0])).then(function(dev_) {
                                if (!is_chrome_app) dev_ = new trezor.Session(transport, dev_.session);
                                deferred.resolve(dev_.initialize().then(function(init_res) {
                                    var outdated = false;
                                    if (init_res.message.major_version < 1) outdated = true;
                                    else if (init_res.message.major_version == 1 &&
                                             init_res.message.minor_version < 3) outdated = true;
                                    if (outdated) {
                                        notices.makeNotice('error', gettext("Outdated firmware. Please upgrade to at least 1.3.0 at http://mytrezor.com/"));
                                        return $q.reject({outdatedFirmware: true});
                                    } else {
                                        return dev_;
                                    }
                                }).then(function(dev) {
                                    trezor_dev = dev;
                                    trezor_dev.on('pin', promptPin);
                                    trezor_dev.on('passphrase', promptPassphrase);
                                    trezor_dev.on('error', handleError);
                                    trezor_dev.on('button', function () {
                                        handleButton(dev);
                                    });
                                    return trezor_dev;
                                }));
                            }, function(err) {
                                handleError('Opening device failed');
                            });
                        } else if (noModal) {
                            if (noModal == 'retry') return;
                            deferred.reject();
                        } else showModal();
                    }, function() {
                        if (noModal) {
                            if (noModal == 'retry') return;
                            $interval.cancel(tick);
                            deferred.reject();
                        } else showModal();
                    })
                }, 1000);
            }).catch(function(e) {
                if (!silentFailure) {
                    $rootScope.safeApply(function() {
                        // notices.makeNotice('error', gettext('TREZOR initialisation failed') + ': ' + e);
                    });
                }
                deferred.reject({pluginLoadFailed: true})
            });
            return deferred.promise;
        },
        recovery: function(mnemonic) {
            return this.getDevice().then(function(dev) {
                return dev.wipeDevice().then(function(res) {
                    return dev.loadDevice({mnemonic: mnemonic});
                });
            });
        },
        setupSeed: function(mnemonic) {
            var scope = $rootScope.$new(), d = $q.defer(), trezor_dev, modal, service = this;
            scope.trezor = {
                use_gait_mnemonic: !!mnemonic,
                store: function() {
                    this.setting_up = true;
                    var store_d;
                    if (mnemonic) {
                        store_d = service.recovery(mnemonic);
                    } else {
                        store_d = trezor_dev.resetDevice({strength: 256});
                    }
                    store_d.then(function() {
                        modal.close();
                        d.resolve();
                    }).catch(function(err) {
                        this.setting_up = false;
                        if (err.message) return;  // handled by handleError in services.js
                        notices.makeNotice('error', err);
                    });
                },
                reuse: function() {
                    modal.close();
                    d.resolve();
                }
            };
            var do_modal = function() {
                modal = $uibModal.open({
                    templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_trezor_setup.html',
                    scope: scope
                });
                modal.result.catch(function() { d.reject(); });
            }
            this.getDevice().then(function(trezor_dev_) {
                trezor_dev = trezor_dev_;
                trezor_dev.getPublicKey([]).then(function(pk) {
                    scope.trezor.already_setup = true;
                    do_modal();
                }, function(err) {
                    if (err.code != 11) {  // Failure_NotInitialized
                        notices.makeNotice("error", err.message)
                    }
                    do_modal();
                })
            });
            return d.promise;
        }
    };
}]).factory('btchip', ['$q', '$interval', '$uibModal', '$rootScope', 'mnemonics', 'notices', 'focus', 'cordovaReady', '$injector',
        function($q, $interval, $uibModal, $rootScope, mnemonics, notices, focus, cordovaReady, $injector) {

    /**@TODO
        This should be broken into 2 services
        1 service should monitor and event based on the state of hardware wallets
        and expose an API for interacting with them
        a second service should manage UI events based on the behavior of these
        wallets. This isolation will make HW wallets easier to support and the 
        UI's related to them easier to maintain... it will also allow us to 
        cleave off any reusable code for HW wallets we want to publish into the
        ecosystem

        This will require a refactor since currently the business logic and UI 
        control flow are bound directly to each other
    */
    var cardFactory;
    if (window.ChromeapiPlugupCardTerminalFactory) {
        cardFactory = new ChromeapiPlugupCardTerminalFactory();
        cardFactoryBootloader = new ChromeapiPlugupCardTerminalFactory(0x1808);
    }

    var BTChipCordovaWrapper = function() {
        var dongle = {
            disconnect_async: function() {
                var d = $q.defer();
                cordova.exec(function() {
                    d.resolve();
                }, function(fail) {
                    d.reject(fail);
                }, "BTChip", "disconnect", []);
                return d.promise;
            }
        }
        return {
            app: {
                getFirmwareVersion_async: function() {
                    var d = Q.defer();
                    cordova.exec(function(result) {
                        result = new ByteString(result, HEX);
                        d.resolve({
                            compressedPublicKeys: result.byteAt(0) == 0x01,
                            firmwareVersion: result.bytes(1)
                        });
                    }, function(fail) {
                        d.reject(fail);
                    }, "BTChip", "getFirmwareVersion", []);
                    return d.promise;
                },
                verifyPin_async: function(pin) {
                    if (this.pin_verified) return $q.when();
                    var that = this;
                    var d = Q.defer();
                    cordova.exec(function(result) {
                        that.pin_verified = true;
                        d.resolve();
                    }, function(fail) {
                        d.reject(fail);
                    }, "BTChip", "verifyPin", [pin.toString(HEX)]);
                    return d.promise;
                },
                getWalletPublicKey_async: function(path) {
                    var d = Q.defer();
                    cordova.exec(function(result) {
                        d.resolve({
                            bitcoinAddress: {value: result.bitcoinAddress},
                            chainCode: new ByteString(result.chainCode, HEX),
                            publicKey: new ByteString(result.publicKey, HEX),
                        });
                    }, function(fail) {
                        d.reject(fail);
                    }, "BTChip", "getWalletPublicKey", [path]);
                    return d.promise;
                },
                signMessagePrepare_async: function(path, msg) {
                    var d = Q.defer();
                    cordova.exec(function(result) {
                        d.resolve(result);
                    }, function(fail) {
                        d.reject(fail);
                    }, "BTChip", "signMessagePrepare", [path, msg.toString(HEX)]);
                    return d.promise;
                },
                signMessageSign_async: function(pin) {
                    var d = Q.defer();
                    cordova.exec(function(result) {
                        d.resolve(new ByteString(result, HEX));
                    }, function(fail) {
                        d.reject(fail);
                    }, "BTChip", "signMessageSign", [pin.toString(HEX)]);
                    return d.promise;
                },
                gaStartUntrustedHashTransactionInput_async: function(newTransaction, tx, i) {
                    var d = Q.defer();
                    var inputs = [];
                    for (var j = 0; j < tx.ins.length; j++) {
                        var input = tx.ins[j];
                        var txhash = input.hash.toString('hex');
                        var outpointAndSequence = new Bitcoin.Buffer.Buffer(8);
                        outpointAndSequence.writeUInt32LE(input.index, 0);
                        outpointAndSequence.writeUInt32LE(input.sequence, 4);
                        outpointAndSequence = outpointAndSequence.toString('hex');
                        inputs.push(txhash + outpointAndSequence);
                    }
                    var script = tx.ins[i].script.toString('hex');
                    cordova.exec(function(result) {
                        d.resolve(result);
                    }, function(fail) {
                        d.reject(fail);
                    }, "BTChip", "startUntrustedTransaction", [newTransaction, i, inputs, script]);
                    return d.promise;
                },
                gaUntrustedHashTransactionInputFinalizeFull_async: function(tx) {
                    var d = Q.defer();
                    cordova.exec(function(result) {
                        d.resolve(result);
                    }, function(fail) {
                        d.reject(fail);
                    }, "BTChip", "finalizeInputFull", [tx.serializeOutputs().toString('hex')]);
                    return d.promise;
                },
                signTransaction_async: function(path, transactionAuthorization, lockTime) {
                    var d = Q.defer();
                    cordova.exec(function(result) {
                        d.resolve(new ByteString(result, HEX));
                    }, function(fail) {
                        d.reject(fail);
                    }, "BTChip", "untrustedHashSign", [path, lockTime]);
                    return d.promise;
                }
            },
            dongle: dongle
        }
    }
    var pinModalCallbacks = [], pinNotCancelable = false, devnum = 0;
    return {
        _setupWrappers: function(btchip) {
            // wrap some functions to allow using them even after disconnecting the dongle
            // (prompting user to reconnect and enter pin)
            var service = this;
            var WRAP_FUNCS = [
                'gaStartUntrustedHashTransactionInput_async',
                'signMessagePrepare_async'
            ];
            for (var i = 0; i < WRAP_FUNCS.length; i++) { (function(func_name) {
                btchip[func_name] = function() {
                    var deferred = $q.defer();
                    var origArguments = arguments;
                    try {
                        var d = btchip.app[func_name].apply(btchip.app, arguments)
                    } catch (e) {
                        // handle `throw "Connection is not open"` gracefully - getDevice() below
                        var d = $q.reject();
                    }
                    d.then(function(data) {
                        deferred.resolve(data);
                    }, function(error) {
                        if (!error || !error.indexOf || error.indexOf('Write failed') != -1) {
                            notices.makeNotice('error', gettext('BTChip communication failed'));
                            // no btchip - try polling for it
                            service.getDevice().then(function(btchip_) {
                                btchip.app = btchip_.app;
                                btchip.dongle = btchip_.dongle;
                                deferred.resolve(btchip[func_name].apply(btchip, origArguments));
                            });
                        } else {
                            if (error.indexOf("6982") >= 0) {
                                btchip.app.pin_verified = false;
                                // setMsg("Dongle is locked - enter the PIN");
                                return service.promptPin('', function(err, pin) {
                                    if (!pin) {
                                        deferred.reject();
                                        return;
                                    }
                                    return btchip.app.verifyPin_async(new ByteString(pin, ASCII)).then(function() {
                                        var d = $q.defer();  // don't call two functions at once in pinModalCallbacks
                                        btchip[func_name].apply(btchip, origArguments).then(function(ret) {
                                            deferred.resolve();
                                            d.resolve(ret);
                                        })
                                        return d.promise;
                                    }).fail(function(error) {
                                        btchip.dongle.disconnect_async();
                                        if (error.indexOf("6982") >= 0) {
                                            notices.makeNotice("error", gettext("Invalid PIN"));
                                        } else if (error.indexOf("6985") >= 0) {
                                            notices.makeNotice("error", gettext("Dongle is not set up"));
                                        } else if (error.indexOf("6faa") >= 0) {
                                            notices.makeNotice("error", gettext("Dongle is locked - reconnect the dongle and retry"));
                                        } else {
                                            notices.makeNotice("error", error);
                                        }
                                        deferred.reject();
                                    });
                                });
                            } else if (error.indexOf("6985") >= 0) {
                                notices.makeMessage('error', gettext("Dongle is not set up"));
                                deferred.reject();
                            } else if (error.indexOf("6faa") >= 0) {
                                notices.makeMessage('error', gettext("Dongle is locked - remove the dongle and retry"));
                                deferred.reject();
                            }
                        }
                    });
                    return deferred.promise;
                }
            })(WRAP_FUNCS[i]) }
            return btchip;
        },
        promptPin: function(type, callback) {
            pinModalCallbacks.push({cb: callback, devnum: devnum});
            if (pinModalCallbacks.length > 1) return;  // modal already displayed
            var scope, modal;

            scope = angular.extend($rootScope.$new(), {
                pin: '',
                type: type,
                pinNotCancelable: pinNotCancelable
            });
            pinNotCancelable = false;

            modal = $uibModal.open({
                templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_btchip_pin.html',
                size: 'sm',
                windowClass: 'pinmodal',
                backdrop: 'static',
                keyboard: false,
                scope: scope
            });

            focus('btchipPinModal');

            return modal.result.then(
                function (res) {
                    var oldCallbacks = pinModalCallbacks.slice();
                    var d = $q.when();
                    for (var i = 0; i < oldCallbacks.length; i++) {
                        if (oldCallbacks[i].devnum == devnum) {
                            (function(i) { d = d.then(function() {
                                return oldCallbacks[i].cb(null, res);
                            }); })(i);
                        }
                    }
                    pinModalCallbacks = [];
                    return d;
                },
                function (err) {
                    var oldCallbacks = pinModalCallbacks.slice();
                    for (var i = 0; i < oldCallbacks.length; i++) {
                        oldCallbacks[i].cb(err);
                    }
                    pinModalCallbacks = [];
                }
            );
        },
        getDevice: function(noModal, modalNotDisableable, existing_device) {
            var service = this;
            var deferred = $q.defer();

            if (window.cordova && cordova.platformId == 'ios') return deferred.promise;
            if (!cardFactory && !window.cordova) return $q.reject();

            var modal, showModal = function() {
                if (!noModal && !modal) {
                    $rootScope.safeApply(function() {
                        options = {
                            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_usb_device.html',
                        };
                        if (modalNotDisableable) {
                            options.scope = angular.extend($rootScope.$new(), {
                                notCancelable: true
                            });
                            options.backdrop = 'static';
                            pinNotCancelable = true;
                        }
                        modal = $uibModal.open(options);
                        $injector.get('hw_detector').modal = modal;
                        modal.result.finally(function() {
                            $interval.cancel(tick);
                        });
                    });
                }
                if (noModal) {
                    if (noModal == 'retry') return;
                    $interval.cancel(tick);
                    deferred.reject();
                }
            };

            var check = cordovaReady(function() {
                if (existing_device) existing_promise = existing_device.app.getFirmwareVersion_async();
                else existing_promise = $q.reject();
                existing_promise.then(function() {
                    $interval.cancel(tick);
                    deferred.resolve(existing_device);
                }, function() {
                    if (window.cordova) {
                        var app_d = $q.defer(), app_promise = app_d.promise;
                        cordova.exec(function(result) {
                            if (result) {
                                var wrapper = new BTChipCordovaWrapper();
                                app_d.resolve({app: wrapper.app, dongle: wrapper.dongle});
                            } else showModal();
                        }, function(fail) {}, "BTChip", "has_dongle", []);
                    } else {
                        var app_promise = cardFactory.list_async().then(function(result) {
                            if (result.length) {
                                return cardFactory.getCardTerminal(result[0]).getCard_async().then(function(dongle) {
                                    devnum += 1;
                                    return {app: new BTChip(dongle), dongle: dongle, devnum: devnum};
                                });
                            } else {
                                cardFactoryBootloader.list_async().then(function(result) {
                                    if (result.length) {
                                        showUpgradeModal();
                                        $interval.cancel(tick);
                                    } else {
                                        showModal();
                                    }
                                });
                            }
                        });
                    }
                    app_promise.then(function(btchip) {
                        btchip.app.getFirmwareVersion_async().then(function(version) {
                            if (noModal) {
                                $interval.cancel(tick);
                            } else if (modal) {
                                modal.close();  // modal close cancels the tick
                            } else {
                                $interval.cancel(tick);
                            }
                            var features = {};
                            var firmwareVersion = version.firmwareVersion.bytes(0, 4);
                            if (firmwareVersion.toString(HEX) < '00010408') {
                                btchip.dongle.disconnect_async();
                                showUpgradeModal();
                                return;
                            }
                            features.signMessageRecoveryParam =
                                firmwareVersion.toString(HEX) >= '00010409';
                            features.quickerVersion =
                                firmwareVersion.toString(HEX) >= '0001040b';
                            deferred.resolve(service._setupWrappers({dongle: btchip.dongle,
                                                                     app: btchip.app,
                                                                     features: features}));
                        });
                    });
                });
            });
            var tick = $interval(check, 1000);
            check();

            return deferred.promise;

            function showUpgradeModal () {
                var notice = gettext("Old BTChip firmware version detected. Please upgrade to at least %s.").replace('%s', '1.4.8');
                if (window.cordova) {
                    notices.makeNotice("error", notice);
                } else {
                    var scope = angular.extend($rootScope.$new(), {
                        firmware_upgrade_message: notice
                    });
                    var modal = $uibModal.open({
                        templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_btchip_fup.html',
                        scope: scope
                    }).result.then(function() {
                        deferred.resolve(service.getDevice(noModal, modalNotDisableable, existing_device));
                    });
                }
            }
        },
        setupSeed: function(mnemonic) {
            var deferred = $q.defer();
            var service = this;

            this.getDevice().then(function(btchip_) {
                var scope = $rootScope.$new(),
                    wrong_pin, btchip = btchip_;
                scope.btchip = {
                    already_setup: false,
                    gait_setup: false,
                    use_gait_mnemonic: !!mnemonic,
                    storing: false,
                    seed_progress: 0,
                    reset: function() {
                        this.resetting = true;
                        this.resets_remaining = 3;
                        wrong_pin = '00000000000000000000000000000000';
                        var attempt = function() {
                            btchip.app.verifyPin_async(new ByteString(wrong_pin, ASCII)).then(function() {
                                wrong_pin = '1234';
                                attempt();
                            }).fail(function(error) {
                                $rootScope.$apply(function() {
                                    console.log('reset pin error ' + error);
                                    if (error.indexOf("6982") >= 0 || error.indexOf("63c") >= 0) {
                                        // setMsg("Dongle is locked - enter the PIN");
                                        if (error.indexOf("63c") >= 0) {
                                            scope.btchip.resets_remaining = Number.parseInt(error[error.indexOf("63c") + 3]);
                                        } else {
                                            scope.btchip.resets_remaining -= 1;
                                        }
                                    } else if (error.indexOf("6985") >= 0) {
                                        // var setupText = "Dongle is not set up";
                                        scope.btchip.resets_remaining = 0;
                                    }
                                    scope.btchip.replug_required = true;
                                    if (scope.btchip.resets_remaining) {
                                        service.getDevice('retry').then(function(btchip_) {
                                            btchip = btchip_;
                                            scope.btchip.replug_required = false;
                                            attempt();
                                        })
                                    } else {
                                        service.getDevice('retry').then(function(btchip_) {
                                            btchip = btchip_;
                                            scope.btchip.replug_required = false;
                                            scope.btchip.resetting = false;
                                            scope.btchip.already_setup = false;
                                        });
                                    }
                                });
                            });
                        };
                        attempt();
                    },
                    store: function() {
                        if (!mnemonic) {
                            this.setting_up = true;
                        } else {
                            this.storing = true;
                        }
                        service.promptPin('', function(err, pin) {
                            if (!pin) return;
                            if (mnemonic) seed_deferred = mnemonics.toSeed(mnemonic);
                            else seed_deferred = $q.when();
                            seed_deferred.then(function(seed) {
                                btchip.app.setupNew_async(
                                    0x01,  // wallet mode

                                    0x02 | // deterministic signatures
                                    0x08,  // skip second factor if consuming only P2SH inputs in a transaction

                                    cur_net.pubKeyHash,
                                    cur_net.scriptHash,
                                    new ByteString(pin, ASCII),
                                    undefined,  // wipePin

                                    // undefined,  // keymapEncoding
                                    // true,  // restoreSeed
                                    seed && new ByteString(seed, HEX) // bip32Seed
                                ).then(function() {
                                    btchip.app.setKeymapEncoding_async().then(function() {
                                        $rootScope.$apply(function() {
                                            scope.btchip.storing = scope.btchip.setting_up = false;
                                            scope.btchip.gait_setup = true;
                                            scope.btchip.replug_for_backup = !mnemonic;
                                            deferred.resolve({pin: pin});
                                        });
                                    }).fail(function(error) {
                                        notices.makeNotice('error', error);
                                        console.log('setKeymapEncoding_async error: ' + error);
                                    });
                                }).fail(function(error) {
                                    notices.makeNotice('error', error);
                                    console.log('setupNew_async error: ' + error);
                                });
                            }, null, function(progress) {
                                scope.btchip.seed_progress = progress;
                            });
                        });
                    }
                };
                var do_modal = function() {
                    $uibModal.open({
                        templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_btchip_setup.html',
                        scope: scope
                    }).result.finally(function() {
                        btchip.dongle.disconnect_async();
                    });
                }
                btchip.app.getWalletPublicKey_async("").then(function(result) {
                    scope.btchip.already_setup = true;
                    do_modal();
                }).fail(function(error) {
                    if (error.indexOf("6982") >= 0) {
                        // setMsg("Dongle is locked - enter the PIN");
                        scope.btchip.already_setup = true;
                    } else if (error.indexOf("6985") >= 0) {
                        // var setupText = "Dongle is not set up";
                    } else if (error.indexOf("6faa") >= 0) {
                        // setMsg("Dongle is locked - remove the dongle and retry");
                        scope.btchip.already_setup = true;
                    }
                    do_modal();
                });
            });

            return deferred.promise;
        }
    }
}]).factory('bip38', ['$q', '$uibModal', 'mnemonics', 'focus', function($q, $uibModal, mnemonics, focus) {
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
                }, "BIP38", method, [Array.from(data), password]);
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
            var worker = new Worker("/static/js/greenwallet/signup/bip38_worker.js");
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
        var modal = $uibModal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signuplogin/modal_encryption_password.html',
            scope: $scope
        });
        modal.opened.then(function() { focus('encryptPasswordModal'); })
        return d.promise;
    };
    return bip38Service;
}]).factory('encode_key', ['$q', function($q) {
    var iframe;
    return function(key, passphrase) {
        var data = key.keyPair || key;  // either HDNode or ECPair
        if (!passphrase) {
            return $q.when(data.toWIF());
        } else {
            var is_chrome_app = window.chrome && chrome.storage;
            var d = $q.defer();
            if (window.cordova) {
                cordovaReady(function() {
                    cordova.exec(function(b58) {
                        d.resolve(b58);
                    }, function(fail) {
                        $rootScope.decrementLoading();
                        notices.makeNotice('error', fail);
                        d.reject(fail);
                    }, "BIP38", "encrypt", [
                        Array.from(data.d.toBuffer()),
                        passphrase,
                        (cur_net === Bitcoin.bitcoin.networks.bitcoin ?
                            'BTC' : 'BTT')]);
                })();
            } else if (is_chrome_app) {
                var process = function() {
                    var listener = function(message) {
                        window.removeEventListener('message', listener);
                        d.resolve(message.data);
                    };
                    window.addEventListener('message', listener);
                    iframe.contentWindow.postMessage({
                        eckey: data.toWIF(),
                        network: cur_net,
                        password: passphrase
                    }, '*');
                };
                if (!iframe) {
                    if (document.getElementById("id_iframe_send_bip38")) {
                        iframe = document.getElementById("id_iframe_send_bip38");
                        process();
                    } else {
                        iframe = document.createElement("IFRAME");
                        iframe.onload = process;
                        iframe.setAttribute("src", "/bip38_sandbox.html");
                        iframe.setAttribute("class", "ng-hide");
                        iframe.setAttribute("id", "id_iframe_send_bip38");
                        document.body.appendChild(iframe);
                    }
                } else {
                    process();
                }
            } else {
                var worker = new Worker("/static/js/greenwallet/signup/bip38_worker.js");
                worker.onmessage = function(message) {
                    d.resolve(message.data);
                }
                worker.postMessage({
                    eckey: data.toWIF(),
                    network: cur_net,
                    password: passphrase
                });
            }
            return d.promise;
        }
    };
}]);
