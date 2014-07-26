angular.module('greenWalletReceiveControllers',
    ['greenWalletServices'])
.controller('ReceiveController', ['$rootScope', '$scope', 'wallets', 'tx_sender', 'notices', 'cordovaReady', 'hostname', 'gaEvent', '$modal', '$location', 'qrcode', 'clipboard',
        function InfoController($rootScope, $scope, wallets, tx_sender, notices, cordovaReady, hostname, gaEvent, $modal, $location, qrcode, clipboard) {
    if(!wallets.requireWallet($scope)) return;
    var base_payment_url = 'https://' + hostname + '/pay/' + $scope.wallet.receiving_id + '/';
    $scope.receive = {
        payment_url: base_payment_url,
        show_previous_addresses: function() {
            $rootScope.is_loading += 1;
            tx_sender.call('http://greenaddressit.com/addressbook/get_my_addresses').then(function(data) {
                $scope.receive.my_addresses = data;
                $modal.open({
                    templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_my_addresses.html',
                    scope: $scope
                });
            }, function(err) {
                notices.makeNotice('error', err.desc);
            }).finally(function() { $rootScope.is_loading -= 1; });
        },
        is_bip38: function(privkey) {
            return Bitcoin.BIP38.isBIP38Format(privkey);
        },
        sweep: function() {
            var do_sweep_key = function(key) {
                var pubkey = key.getPub(compressed);
                that.sweeping = true;
                tx_sender.call("http://greenaddressit.com/vault/prepare_sweep_social", pubkey.toBytes(), true).then(function(data) {
                    data.prev_outputs = [];
                    for (var i = 0; i < data.prevout_scripts.length; i++) {
                        data.prev_outputs.push(
                            {privkey: key, script: data.prevout_scripts[i]})
                    }
                    // TODO: verify
                    wallets.sign_and_send_tx(undefined, data, false, null, gettext('Funds swept')).then(function() {
                        $location.url('/info/');
                    }).finally(function() {
                        that.sweeping = false;
                    });
                }, function(error) {
                    that.sweeping = false;
                    if (error.uri == 'http://greenaddressit.com/error#notenoughmoney') {
                        notices.makeNotice('error', gettext('Already swept or no funds found'));
                    } else {
                        notices.makeNotice('error', error.desc);
                    }
                });
            }

            var that = this;
            var key_wif = this.privkey_wif;
            var iframe;
            if (Bitcoin.BIP38.isBIP38Format(key_wif)) {
                that.sweeping = true;
                var errors = {
                    invalid_privkey: gettext('Not a valid encrypted private key'),
                    invalid_passphrase: gettext('Invalid passphrase')
                };
                var is_chrome_app = window.chrome && chrome.storage;
                if (window.cordova) {
                    cordovaReady(function() {
                        cordova.exec(function(data) {
                            $scope.$apply(function() {
                                do_sweep_key(new Bitcoin.ECKey(data));
                            });
                        }, function(fail) {
                            that.sweeping = false;
                            notices.makeNotice('error', errors[fail] || fail);
                        }, "BIP38", "decrypt", [key_wif, that.bip38_password,
                                'BTC']);  // probably not correct for testnet, but simpler, and compatible with our JS impl
                    })();
                } else if (is_chrome_app) {
                    var process = function() {
                        var listener = function(message) {
                            window.removeEventListener('message', listener);
                            that.sweeping = false;
                            if (message.data.error) {
                                notices.makeNotice('error', errors[message.data.error] || message.data.error);
                            } else {
                                do_sweep_key(new Bitcoin.ECKey(message.data));
                            }
                        };
                        window.addEventListener('message', listener);
                        iframe.contentWindow.postMessage({b58: key_wif, password: that.bip38_password}, '*');
                    };
                    if (!iframe) {
                        if (document.getElementById("id_iframe_receive_bip38")) {
                            iframe = document.getElementById("id_iframe_receive_bip38");
                            process();
                        } else {
                            iframe = document.createElement("IFRAME"); 
                            iframe.onload = process;
                            iframe.setAttribute("src", "/bip38_sandbox.html");
                            iframe.setAttribute("class", "ng-hide");
                            iframe.setAttribute("id", "id_iframe_receive_bip38");
                            document.body.appendChild(iframe); 
                        }
                    } else {
                        process();
                    }
                } else {
                    var worker = new Worker(BASE_URL+"/static/js/bip38_worker.min.js");
                    worker.onmessage = function(message) {
                        that.sweeping = false;
                        if (message.data.error) {
                            notices.makeNotice('error', errors[message.data.error] || message.data.error);
                        } else {
                            do_sweep_key(new Bitcoin.ECKey(message.data));
                        }
                    }
                    worker.postMessage({b58: key_wif, password: this.bip38_password});
                }
            } else if (key_wif.indexOf('K') == 0 || key_wif.indexOf('L') == 0 || key_wif.indexOf('5') == 0) { // prodnet
                // || encrypted_key.indexOf('c') == 0 || encrypted_key.indexOf('9') == 0) { // testnet - not supported
                var key_bytes = Bitcoin.base58.decode(key_wif);
                if (key_bytes.length != 38 && key_bytes.length != 37) {
                    notices.makeNotice(gettext('Not a valid private key'));
                    return;
                }
                var expChecksum = key_bytes.slice(-4);
                key_bytes = key_bytes.slice(0, -4);
                var key_words = Bitcoin.convert.bytesToWordArray(key_bytes);
                var checksum = Bitcoin.CryptoJS.SHA256(Bitcoin.CryptoJS.SHA256(key_words));
                checksum = Bitcoin.convert.wordArrayToBytes(checksum);
                if (checksum[0] != expChecksum[0] || checksum[1] != expChecksum[1] || checksum[2] != expChecksum[2] || checksum[3] != expChecksum[3]) {
                    notices.makeNotice(gettext('Not a valid private key'));
                    return;
                }
                if (key_bytes.length == 34) {
                    key_bytes = key_bytes.slice(1, -1);
                    var compressed = true;
                } else {
                    key_bytes = key_bytes.slice(1);
                    var compressed = false;
                }
                do_sweep_key(new Bitcoin.ECKey(Bitcoin.convert.bytesToHex(key_bytes)));
            } else {
                notices.makeNotice(gettext('Not a valid private key'));
                return;
            }
        },
        read_wif_qr_code: function($event) {
            gaEvent('Wallet', 'ReceiveReadWIFQrCode');
            var that = this;
            qrcode.scan($scope, $event, '_receive').then(function(text) {
                gaEvent('Wallet', 'ReceiveReadWIFQrCodeSuccessful');
                $rootScope.safeApply(function() {
                    that.privkey_wif = text;
                });
            }, function(error) {
                gaEvent('Wallet', 'ReceiveReadWIFQrCodeFailed', error);
                notices.makeNotice('error', error);
            });
        },
        stop_scanning_qr_code: function() {
            qrcode.stop_scanning($scope);
        },
        show_sweep: cur_net == 'mainnet'  // no testnet
    };
    var div = {'BTC': 1, 'mBTC': 1000, 'µBTC': 1000000}[$scope.wallet.unit];
    var formatAmountBitcoin = function(amount) {
        var satoshi = Bitcoin.Util.parseValue(amount.toString()).divide(Bitcoin.BigInteger.valueOf(div));
        return Bitcoin.Util.formatValue(satoshi.toString());
    };
    var formatAmountSatoshi = function(amount) {
        var satoshi = Bitcoin.Util.parseValue(amount.toString()).divide(Bitcoin.BigInteger.valueOf(div));
        return satoshi.toString();
    }
    $scope.show_bitcoin_uri = function(show_qr) {
        if ($scope.receive.bitcoin_uri) {
            if (show_qr) $scope.show_url_qr($scope.receive.bitcoin_uri);
        } else {
            gaEvent('Wallet', 'ReceiveShowBitcoinUri');
            tx_sender.call('http://greenaddressit.com/vault/fund').then(function(data) {
                var script = Bitcoin.convert.bytesToWordArray(Bitcoin.convert.hexToBytes(data));
                var hash = Bitcoin.convert.wordArrayToBytes(Bitcoin.Util.sha256ripe160(script));
                var version = Bitcoin.network[cur_net].p2shVersion;
                var address = new Bitcoin.Address(hash, version);
                $scope.receive.bitcoin_address = address.toString();
                $scope.receive.base_bitcoin_uri = $scope.receive.bitcoin_uri = 'bitcoin:' + address.toString();
                if ($scope.receive.amount) {
                    $scope.receive.bitcoin_uri += '?amount=' + formatAmountBitcoin($scope.receive.amount);
                }
                if (show_qr) $scope.show_url_qr($scope.receive.bitcoin_uri);
            });
        }
    }
    $scope.copy_from_clipboard = function(send_tx) {
        clipboard.paste(function(data) {
            console.log(data);
            send_tx.recipient = data;
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
    wallets.addCurrencyConversion($scope, 'receive');
    $scope.$watch('receive.amount', function(newValue, oldValue) {
        if (newValue === oldValue) return;
        if (newValue) {
            $scope.receive.payment_url = base_payment_url + '?amount=' + formatAmountSatoshi(newValue);
            if ($scope.receive.bitcoin_uri) {
                $scope.receive.bitcoin_uri = $scope.receive.base_bitcoin_uri + '?amount=' + formatAmountBitcoin(newValue);
            }
        } else {
            $scope.receive.payment_url = base_payment_url;
            $scope.receive.bitcoin_uri = $scope.receive.base_bitcoin_uri;
        }
    });
}]);
