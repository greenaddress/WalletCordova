angular.module('greenWalletSendControllers',
    ['greenWalletServices'])
.controller('SendController', ['$scope', 'wallets', 'tx_sender', 'cordovaReady', 'notices', 'branches', 'facebook', 'wallets', '$routeParams', 'hostname', 'gaEvent', 'reddit', '$modal', '$location', '$rootScope', '$q', 'parse_bitcoin_uri',
         function SendController($scope, wallets, tx_sender, cordovaReady, notices, branches, facebook, wallets, $routeParams, hostname, gaEvent, reddit, $modal, $location, $rootScope, $q, parse_bitcoin_uri) {
    if (!wallets.requireWallet($scope)) return;
    var verify_tx = function(that, rawtx, destination, satoshis, change_pointer) {
        var d = $q.defer();
        var tx = decode_raw_tx(Crypto.util.hexToBytes(rawtx));

        if (destination && (0 != destination.indexOf('GA'))) {  // we can't verify GA* addresses
            // decode the expected destination address
            var bytes = Bitcoin.Base58.decode(destination);
            var hash = bytes.slice(0, 21);

            var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});

            if (checksum[0] != bytes[21] ||
                checksum[1] != bytes[22] ||
                checksum[2] != bytes[23] ||
                checksum[3] != bytes[24]) {
                    return $q.reject(gettext("Checksum validation failed!"));
            }

            var version = hash.shift();
            if (version != cur_coin_version && version != cur_coin_p2sh_version) {
                return $q.reject(gettext("Version "+version+" not supported!"));
            }

            // verify the first output
            var chunks = tx.outs[0].script.chunks;
            if (version == cur_coin_version) {
                if (chunks.length != 5) return $q.reject(gettext('Invalid pubkey hash script length'));
                if (chunks[0] != Opcode.map.OP_DUP) return $q.reject(gettext('OP_DUP missing'));
                if (chunks[1] != Opcode.map.OP_HASH160) return $q.reject(gettext('OP_HASH160 missing'));
                if (Crypto.util.bytesToHex(chunks[2]) != Crypto.util.bytesToHex(hash)) return $q.reject(gettext('Invalid pubkey hash'));
                if (chunks[3] != Opcode.map.OP_EQUALVERIFY) return $q.reject(gettext('OP_EQUALVERIFY missing'));
                if (chunks[4] != Opcode.map.OP_CHECKSIG) return $q.reject(gettext('OP_CHECKSIG missing'));
            } else if (version == cur_coin_p2sh_version) {
                if (chunks.length != 3) return $q.reject(gettext('Invalid out P2SH script length'));
                if (chunks[0] != Opcode.map.OP_HASH160) return $q.reject(gettext('out OP_HASH160 missing'));
                if (Crypto.util.bytesToHex(chunks[1]) != Crypto.util.bytesToHex(hash)) return $q.reject(gettext('Invalid out P2SH hash'));
                if (chunks[2] != Opcode.map.OP_EQUAL) return $q.reject(gettext('out OP_EQUAL missing'));
            }
        }

        // calculate the inputs value
        var in_value_promises = [];
        var in_value = BigInteger.valueOf(0);
        for (var i = 0; i < tx.ins.length; i++) {
            var outpoint = tx.ins[i].outpoint;
            var txhash = outpoint.hash;
            var bytes = Crypto.util.base64ToBytes(txhash); bytes.reverse();
            txhash = Crypto.util.bytesToHex(bytes);
            in_value_promises.push($scope.wallet.get_tx_output_value(txhash, outpoint.index));
        }
        return $q.all(in_value_promises).then(function(values) {
            for (var i = 0; i < values.length; ++i) {
                if (!values[i]) return $q.reject(gettext('Missing input'));
                in_value = in_value.add(BigInteger.valueOf(values[i]));
            }
            if (in_value.compareTo(BigInteger.valueOf(0)) <= 0)
                // just in case we have some bug in summing, like missing valueOf
                return $q.reject(gettext('Inputs value is not larger than zero'));

            // calculate the outputs value
            if (tx.outs.length < 1 || tx.outs.length > 2) {
                return $q.reject(tx.outs.length + gettext(' is not a valid number of outputs'));
            }
            var bytes = tx.outs[0].value; bytes.reverse();
            var bytes1 = tx.outs[1] && tx.outs[1].value; if (bytes1) bytes1.reverse();
            var out_value = BigInteger.fromByteArrayUnsigned(bytes);
            if (bytes1) {
                out_value = out_value.add(BigInteger.fromByteArrayUnsigned(bytes1));
            }

            // calculate fees
            var fee = in_value.subtract(out_value), recipient_fee = BigInteger.valueOf(0);
            // subtract mod 10000 to allow anti-dust (<5430) fee
            if (that.add_fee == 'recipient') recipient_fee = fee.subtract(fee.mod(BigInteger.valueOf(10000)));

            // check output value
            if (BigInteger.fromByteArrayUnsigned(bytes).compareTo(
                    BigInteger.valueOf(satoshis).
                        subtract(BigInteger.valueOf(recipient_fee))) != 0) {
                return $q.reject(gettext('Invalid output value'));
            }

            // check fee
            var kB = Math.ceil(rawtx.length / 1000) * 2;
            var expectedMaxFee = BigInteger.valueOf(10000).multiply(BigInteger.valueOf(kB));
            if (fee.compareTo(expectedMaxFee) > 0) {
                return $q.reject(gettext('Fee is too large (%1, expected at most %2)').replace('%1', fee.toString()).replace('%2', expectedMaxFee.toString()));
            }
            var expectedMinFee = BigInteger.valueOf(10000);
            if (fee.compareTo(expectedMinFee) < 0) {
                return $q.reject(gettext('Fee is too small (%1, expected at lest %2)').replace('%1', fee.toString()).replace('%2', expectedMinFee.toString()));
            }

            // check change output if present
            if (tx.outs.length == 2) {
                var change_branch = $scope.wallet.hdwallet.subkey(branches.REGULAR, false, false);
                var change_key = change_branch.subkey(change_pointer, false, false).public_key;
                var change_key_bytes = change_key.getEncoded(true);

                var gawallet = new GAHDWallet({public_key_hex: deposit_pubkey, chain_code_hex: deposit_chaincode}).subkey(1, false, false);
                var change_gait_key = gawallet.subpath($scope.wallet.gait_path).subkey(change_pointer, false, false);

                var script_to_hash = new Bitcoin.Script();
                script_to_hash.writeOp(Opcode.map.OP_2);
                if ($scope.wallet.old_server) {
                    script_to_hash.writeBytes(Crypto.util.hexToBytes(deposit_pubkey));
                } else {
                    script_to_hash.writeBytes(change_gait_key.public_key.getEncoded(true));
                }
                script_to_hash.writeBytes(change_key_bytes);
                script_to_hash.writeOp(Opcode.map.OP_2);
                script_to_hash.writeOp(Opcode.map.OP_CHECKMULTISIG);

                var hash160 = Bitcoin.Util.sha256ripe160(script_to_hash.buffer);
                hash160 = Crypto.util.bytesToHex(hash160);

                var chunks = tx.outs[1].script.chunks;
                if (chunks.length != 3) return $q.reject(gettext('Invalid change P2SH script length'));
                if (chunks[0] != Opcode.map.OP_HASH160) return $q.reject(gettext('change OP_HASH160 missing'));
                if (Crypto.util.bytesToHex(chunks[1]) != hash160) return $q.reject(gettext('Invalid change P2SH hash'));
                if (chunks[2] != Opcode.map.OP_EQUAL) return $q.reject(gettext('change OP_EQUAL missing'));
            }

            return {success: true};
        });
    };
    var iframe;
    var mul = {'BTC': 1, 'mBTC': 1000, 'µBTC': 1000000}[$scope.wallet.unit];
    $scope.send_tx = {
        add_fee: 'sender',
        recipient: $routeParams.contact ? JSON.parse(UTF8.bytesToString(Crypto.util.base64ToBytes($routeParams.contact))) : null,
        read_qr_code: cordovaReady(function()  {
            gaEvent('Wallet', 'SendReadQrCode');
            var that = this;
            cordova.plugins.barcodeScanner.scan(
                function (result) {
                    console.log("We got a barcode\n" +
                    "Result: " + result.text + "\n" +
                    "Format: " + result.format + "\n" +
                    "Cancelled: " + result.cancelled);
                    if (!result.cancelled && result.format == "QR_CODE") {
                        gaEvent('Wallet', 'SendReadQrCodeSuccessful');
                        $scope.$apply(function() {
                            parsed_uri = parse_bitcoin_uri(result.text);
                            if (parsed_uri[0]) {
                                that.recipient = parsed_uri[0];
                                if (parsed_uri[1]) {
                                    that.amount = btcToUnit(parsed_uri[1]);
                                }
                            } else {
                                that.recipient = result.text;
                            }
                        });
                    }
                }, 
                function (error) {
                    console.log("Scanning failed: " + error);
                }
            );
        }),
        do_send_fb: function(that, enckey, satoshis, key, pointer) {
            $scope.send_fb_via_fb = function() {
                $scope.send_fb_via_fb_clicked = true;
                $rootScope.is_loading += 1;
                facebook.login({}).then(function() {
                    $rootScope.is_loading -= 1;
                    FB.ui({
                        method: 'send',
                        link: 'https://' + hostname + '/redeem/' + enckey + '/?amount=' + satoshis,
                        to: that.recipient.address
                    });
                }, function() {
                    $rootScope.is_loading -= 1;
                    notices.makeNotice('error', gettext('Facebook login failed'));
                });
                
            }
            $scope.send_fb_via_fb_clicked = false;
            $rootScope.is_loading -= 1;
            $modal.open({
                templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_fb_message.html',
                scope: $scope
            }).result.then(function() {
                $location.url('/transactions/');
            }, function() {
                // cancel - reverse the tx
                $rootScope.is_loading += 1;
                tx_sender.call("http://greenaddressit.com/vault/prepare_sweep_social",
                        key.public_key.getEncoded(true), false).then(function(data) {
                    data.prev_outputs = [];
                    for (var i = 0; i < data.prevout_scripts.length; i++) {
                        data.prev_outputs.push(
                            {branch: branches.EXTERNAL, pointer: pointer,
                             script: data.prevout_scripts[i]})
                    }
                    wallets.sign_and_send_tx(undefined, data, true, null, gettext('Transaction reversed!')).finally(function() {
                        $rootScope.is_loading -= 1;
                        $location.url('/transactions/');
                    });  // priv_der=true
                }, function(error) {
                    $rootScope.is_loading -= 1;
                    gaEvent('Wallet', 'TransactionsTabRedeemFailed', error.desc);
                    notices.makeNotice('error', error.desc);
                });
            });            
        },
        do_send_email: function(that, enckey, satoshis) {
            tx_sender.call("http://greenaddressit.com/vault/send_email", that.recipient.address,
                    'https://' + hostname + '/redeem/' + enckey + '/?amount=' + satoshis).then(
                function() {
                    $rootScope.is_loading -= 1;
                    notices.makeNotice('success', gettext('Email sent'));
                    $location.url('/transactions/');
                }, function(err) {
                    $rootScope.is_loading -= 1;
                    notices.makeNotice('error', gettext('Failed sending email') + ': ' + err.desc);
                }
            );
        },
        do_send_reddit: function(that, enckey, satoshis) {
            if ($scope.wallet.send_from) $scope.wallet.send_from = null;
            tx_sender.call("http://greenaddressit.com/vault/send_reddit", that.recipient.address,
                    'https://' + hostname + '/redeem/' + enckey + '/?amount=' + satoshis).then(
                function(json) {
                    $rootScope.is_loading -= 1;
                    notices.makeNotice('success', gettext('Reddit message sent'));
                    $location.url('/transactions/');
                }, function(err) {
                    $rootScope.is_loading -= 1;
                    notices.makeNotice('error', gettext('Failed sending Reddit message') + ': ' + err.desc);
                }
            );
        },
        _send_social_ga: function(satoshis) {
            var that = this, to_addr = {type: this.recipient.type,
                                        id: this.recipient.address};
            var priv_data = {social_destination: that.recipient.name};
            if ($scope.wallet.send_from) priv_data.reddit_from = $scope.wallet.send_from;
            tx_sender.call("http://greenaddressit.com/vault/prepare_tx", satoshis, to_addr, this.add_fee,
                           priv_data).then(function(data) {
                wallets.sign_and_send_tx($scope, data).then(function() {
                    if ($scope.wallet.send_from) $scope.wallet.send_from = null;
                    $location.url('/transactions/');
                }).finally(function() { that.sending = false; });
            }, function(error) {
                that.sending = false;
                notices.makeNotice('error', error.desc);
            });
        },
        amount_to_satoshis: function(amount) {
            var div = {'BTC': 1, 'mBTC': 1000, 'µBTC': 1000000}[$scope.wallet.unit];
            return Bitcoin.Util.parseValue(amount).divide(BigInteger.valueOf(div)).toString();
        },
        send_social: function(do_send) {
            var that = this;
            var satoshis = that.amount_to_satoshis(this.amount);
            if (this.recipient.has_wallet) {
                this._send_social_ga(satoshis);
                return;
            } else if (!that.passphrase && !$scope.wallet.send_unencrypted) {
                notices.makeNotice('error', gettext('You must provide encryption passphrase.'));
                that.sending = false;
                return;
            }
            $rootScope.is_loading += 1;
            tx_sender.call("http://greenaddressit.com/vault/get_next_private_derived_pointer").then(function(pointer) {
                var key = $scope.wallet.hdwallet.subkey(branches.EXTERNAL, true, true);
                key = key.subkey(pointer, true, true);
                var to_addr = key.getBitcoinAddress().toString();
                var add_fee = that.add_fee;
                var priv_data = {pointer: pointer,
                                 pubkey: key.public_key.getEncoded(true),
                                 social_destination: that.recipient.name,
                                 external_private: true};
                if ($scope.wallet.send_from) priv_data.reddit_from = $scope.wallet.send_from;
                tx_sender.call("http://greenaddressit.com/vault/prepare_tx", satoshis, to_addr, add_fee, priv_data).then(function(data) {
                    verify_tx(that, data.tx, key.getBitcoinAddress().toString(), satoshis, data.change_pointer).then(function() {
                        wallets.sign_and_send_tx($scope, data, false, undefined, false).then(function() {
                            that.encrypted_key = null;
                            var base58Check = {
                              encode: function(buf) {
                                var checkedBuf = [].concat(buf);
                                var hash = Crypto.SHA256(Crypto.SHA256(buf, {asBytes: true}), {asBytes: true});
                                checkedBuf = checkedBuf.concat(hash.slice(0, 4));
                                return B58.encode(checkedBuf);
                              }
                            };
                            var addr_ascii = key.getBitcoinAddress().toString();
                            var salt = Crypto.SHA256(Crypto.SHA256(addr_ascii, {asBytes: true}), {asBytes: true}).slice(0, 4);
                            var data = key.secret_exponent_bytes;
                            if ($scope.wallet.send_unencrypted) {
                                if (cur_coin == 'BTT') {
                                    var version = 0xef;
                                } else {
                                    var version = 0x80;
                                }
                                data.unshift(version);
                                data.push(0x01);  // compressed
                                do_send(that, base58Check.encode(data), satoshis);
                            } else {
                                var is_chrome_app = window.chrome && chrome.storage;
                                if (window.cordova) {
                                    cordovaReady(function() {
                                        cordova.exec(function(b58) {
                                            do_send(that, b58, satoshis, key, pointer);
                                        }, function(fail) {
                                            $rootScope.is_loading -= 1;
                                            notices.makeNotice('error', fail);
                                        }, "BIP38", "encrypt", [key.secret_exponent_bytes, that.passphrase, cur_coin]);
                                    })();
                                } else if (is_chrome_app) {
                                    var process = function() {
                                        // TODO DRY
                                        var listener = function(message) {
                                            window.removeEventListener('message', listener);
                                            var flagbyte = 128 + 64 + 0x20;  // 0x20 - compressed
                                            var enc = [0x01, 0x42, flagbyte];
                                            enc = enc.concat(salt);
                                            enc = enc.concat(message.data.slice(0, 32));
                                            var b58 = base58Check.encode(enc);
                                            do_send(that, b58, satoshis, key, pointer);
                                        };
                                        window.addEventListener('message', listener);
                                        iframe.contentWindow.postMessage({data: data,
                                                                          key: that.passphrase,
                                                                          salt: salt}, '*');
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
                                    var worker = new Worker("/static/js/bip38_worker.min.js");
                                    worker.onmessage = function(message) {
                                        var flagbyte = 128 + 64 + 0x20;  // 0x20 - compressed
                                        var enc = [0x01, 0x42, flagbyte];
                                        enc = enc.concat(salt);
                                        enc = enc.concat(message.data.slice(0, 32));
                                        var b58 = base58Check.encode(enc);
                                        do_send(that, b58, satoshis, key, pointer);
                                    }
                                    worker.postMessage({data: data,
                                                        key: that.passphrase,
                                                        salt: salt});
                                }
                            }
                        }, function(error) { 
                            $rootScope.is_loading -= 1;
                        }).finally(function() { that.sending = false; });
                    }, function(error) {
                        $rootScope.is_loading -= 1;
                        that.sending = false;
                        notices.makeNotice('error', gettext('Transaction verification failed: ' + error + '. Please contact support.'))
                    })
                }, function(error) {
                    $rootScope.is_loading -= 1;
                    that.sending = false;
                    notices.makeNotice('error', error.desc);
                });
            }, function(error) {
                $rootScope.is_loading -= 1;
                that.sending = false;
                notices.makeNotice('error', error.desc);
            });
        },
        send_address: function() {
            var to_addr = this.recipient.constructor === String ? this.recipient : this.recipient.address;
            var parsed_uri = parse_bitcoin_uri(to_addr);
            if (parsed_uri[0]) to_addr = parsed_uri[0];
            var that = this;
            var satoshis = that.amount_to_satoshis(that.amount);
            $rootScope.is_loading += 1;
            tx_sender.call("http://greenaddressit.com/vault/prepare_tx", satoshis, to_addr, this.add_fee, null).then(function(data) {
                return verify_tx(that, data.tx, to_addr, satoshis, data.change_pointer).then(function() {
                    return wallets.sign_and_send_tx($scope, data).then(function() {
                        $location.url('/transactions/');
                    });
                }, function(error) {
                    notices.makeNotice('error', gettext('Transaction verification failed: ' + error + '. Please contact support.'))
                });
            }, function(error) {
                notices.makeNotice('error', error.desc);
            }).finally(function() { $rootScope.is_loading -= 1; that.sending = false; });;
        },
        send_to_reddit: function() {
            var that = this;
            tx_sender.call("http://greenaddressit.com/addressbook/reddit_user_has_wallet", this.recipient.address.replace('reddit:', '')).then(function(has_wallet) {
                that.recipient.address = that.recipient.address.replace('reddit:', '');
                if (has_wallet) {
                    var satoshis = that.amount_to_satoshis(that.amount);
                    that._send_social_ga(satoshis);
                } else {
                    that.send_social(that.do_send_reddit);
                }
            }, function(error) {
                that.sending = false;
                notices.makeNotice('error', error.desc);
            });
            
        },
        send_money: function() {
            if (isNaN(parseFloat(this.amount))) {
                notices.makeNotice('error', gettext('Invalid amount'));
                return;
            }
            if (!this.recipient) {
                notices.makeNotice('error', gettext('Please provide a recipient'));
                return;   
            }
            this.sending = true;
            if (this.recipient.type == 'facebook') {
                gaEvent('Wallet', 'SendToFacebook');
                this.send_social(this.do_send_fb);
            } else if (this.recipient.type == 'email') {
                gaEvent('Wallet', 'SendToEmail');
                this.send_social(this.do_send_email);
            } else if (this.recipient.type == 'address') {
                gaEvent('Wallet', 'SendToAddress');
                this.send_address();
            } else if (this.recipient.type == 'reddit') {
                gaEvent('Wallet', 'SendToReddit');
                this.send_to_reddit();
            } else if (this.recipient.constructor === String) {
                if (this.recipient.indexOf('@') != -1) {
                    gaEvent('Wallet', 'SendToNewEmail');
                    this.recipient = {type: 'email', name: this.recipient, address: this.recipient};
                    this.send_social(this.do_send_email);
                } else if (this.recipient.indexOf('reddit:') == 0) {
                    gaEvent('Wallet', 'SendToNewReddit');
                    this.recipient = {type: 'reddit', name: this.recipient, address: this.recipient};
                    this.send_to_reddit();
                } else {
                    gaEvent('Wallet', 'SendToNewAddress');
                    this.send_address();
                }
            } else {
                alert('Unsupported recipient type');
            }
        },
        recipient_is_btcaddr: function() {
            return !this.recipient ||
                (this.recipient.constructor === String &&
                    this.recipient.indexOf('@') == -1 &&
                    this.recipient.indexOf('reddit') != 0) ||
                this.recipient.type == 'address' ||
                this.recipient.has_wallet;
        },
        send_to_priv_done: function() {
            this.encrypted_key = undefined;
        }
    };
    var btcToUnit = function(btc) {
        var amount_satoshi = Bitcoin.Util.parseValue(btc);
        return Bitcoin.Util.formatValue(amount_satoshi.multiply(BigInteger.valueOf(mul)));
    }
    $scope.$watch('send_tx.recipient', function(newValue, oldValue) {
        if (newValue === oldValue) return;
        var parsed_uri = parse_bitcoin_uri(newValue);
        if (parsed_uri[1]) {    
            $scope.send_tx.amount = btcToUnit(parsed_uri[1]);
        }
    });
    $scope.$watch('send_tx.amount', function(newValue, oldValue) {
        if (newValue !== oldValue) {
            var parsed_uri = parse_bitcoin_uri($scope.send_tx.recipient);
            if (parsed_uri[1] && newValue != btcToUnit(parsed_uri[1])) {
                // replace the URI with recipient when amount is changed
                $scope.send_tx.recipient = parsed_uri[0];
            }
        }
    });
    if ($scope.send_tx.recipient && $scope.send_tx.recipient.amount) {
        $scope.send_tx.amount = Bitcoin.Util.formatValue(
            new BigInteger($scope.send_tx.recipient.amount.toString()).multiply(BigInteger.valueOf(mul)));
    }
    wallets.addCurrencyConversion($scope, 'send_tx');
}]);
