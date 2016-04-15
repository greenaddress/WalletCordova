angular.module('greenWalletTransactionsControllers',
    ['greenWalletServices'])
.controller('TransactionsController', ['$scope', 'wallets', 'tx_sender', 'notices', 'branches', '$uibModal', 'gaEvent', '$timeout', '$q', 'encode_key', 'hostname',
        function TransactionsController($scope, wallets, tx_sender, notices, branches, $uibModal, gaEvent, $timeout, $q, encode_key, hostname) {
    // required already by InfoController
    // if(!wallets.requireWallet($scope)) return;

    var calcRedeemAndKeyPairs = function(subaccount, pubkey_pointer) {
        var gawallet = new Bitcoin.bitcoin.HDNode(
            Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(
                new Bitcoin.Buffer.Buffer(deposit_pubkey, 'hex'),
                cur_net
            ),
            new Bitcoin.Buffer.Buffer(deposit_chaincode, 'hex')
        );
        var gaKey;
        if (subaccount) {
            gaKey = gawallet.derive(3).then(function (branch) {
                return branch.subpath($scope.wallet.gait_path);
            }).then(function (gawallet) {
                return gawallet.derive(subaccount);
            });
        } else {
            gaKey = gawallet.derive(1).then(function (branch) {
                return branch.subpath($scope.wallet.gait_path);
            });
        }
        gaKey = gaKey.then(function (gawallet) {
            return gawallet.derive(pubkey_pointer);
        });
        var userKey = $q.when($scope.wallet.hdwallet);
        if (subaccount) {
            var derive_hd = function() {
                return $q.when($scope.wallet.hdwallet.deriveHardened(branches.SUBACCOUNT)).then(function(subaccounts_branch) {
                    return $q.when(subaccounts_branch.deriveHardened(subaccount));
                });
            }
            var derive_btchip = function() {
                return $scope.wallet.btchip.app.getWalletPublicKey_async("3'/"+subaccount+"'").then(function(result) {
                    var pubHex = result.publicKey.toString(HEX)
                    var chainCode = result.chainCode.toString(HEX)
                    var pubKey = Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(
                        new Bitcoin.Buffer.Buffer(pubHex, 'hex'),
                        cur_net
                    );
                    pubKey.compressed = true;
                    var subaccount = new Bitcoin.bitcoin.HDNode(
                        pubKey,
                        new Bitcoin.Buffer.Buffer(chainCode, 'hex')
                    );
                    return subaccount;
                });
            }
            var derive_trezor = function() {
                return $scope.wallet.trezor_dev.getPublicKey([3 + 0x80000000, subaccount + 0x80000000]).then(function(result) {
                    return Bitcoin.bitcoin.HDNode.fromBase58(result.message.xpub);
                })
            }
            var derive_fun;
            if ($scope.wallet.hdwallet.keyPair.d) derive_fun = derive_hd;
            else if ($scope.wallet.trezor_dev) derive_fun = derive_trezor;
            else derive_fun = derive_btchip;
            userKey = derive_fun();
        }
        var userKey = userKey.then(function (key) {
            return key.derive(branches.REGULAR);
        }).then(function (branch) {
            return branch.derive(pubkey_pointer)
        });
        var is_2of3 = false, cur_subaccount = null;
        for (var j = 0; j < $scope.wallet.subaccounts.length; j++) {
            if ($scope.wallet.subaccounts[j].pointer == subaccount &&
                $scope.wallet.subaccounts[j].type == '2of3') {
                is_2of3 = true;
                cur_subaccount = $scope.wallet.subaccounts[j];
                break;
            }
        }
        var twoOfThreeKey;
        if (is_2of3) {
            twoOfThreeKey = new Bitcoin.bitcoin.HDNode(
                Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(
                    new Bitcoin.Buffer.Buffer(cur_subaccount['2of3_backup_pubkey'], 'hex'),
                    cur_net
                ),
                new Bitcoin.Buffer.Buffer(cur_subaccount['2of3_backup_chaincode'], 'hex')
            );
            twoOfThreeKey = twoOfThreeKey.derive(1).then(function (branch) {
                return branch.derive(pubkey_pointer);
            });
        } else {
            twoOfThreeKey = $q.when(null);
        }
        return $q.all([gaKey, userKey, twoOfThreeKey]).then(function(keys) {
            var keys_bufs = [keys[0].keyPair.getPublicKeyBuffer(),
                             keys[1].keyPair.getPublicKeyBuffer()];
            if (keys[2]) {
                keys_bufs.push(keys[2].keyPair.getPublicKeyBuffer());
            }
            return {
                gaKey: keys[0],
                userKey: keys[1],
                redeemScript: Bitcoin.bitcoin.script.multisigOutput(
                    2,
                    keys_bufs
                )
            }
        });
    };

    var _redeem = function(transaction) {
        gaEvent('Wallet', 'TransactionsTabRedeem');
        var key = $q.when($scope.wallet.hdwallet);
        if ($scope.wallet.current_subaccount) {
            key = key.then(function(key) {
                return key.deriveHardened(branches.SUBACCOUNT);
            }).then(function(key) {
                return key.deriveHardened($scope.wallet.current_subaccount);
            })
        }
        key = key.then(function(key) {
            return key.deriveHardened(branches.EXTERNAL);
        }).then(function(key) {
            return key.deriveHardened(transaction.pubkey_pointer);
        });
        return key.then(function(key) {
            return tx_sender.call("http://greenaddressit.com/vault/prepare_sweep_social",
                    Array.from(key.keyPair.getPublicKeyBuffer()), false, $scope.wallet.current_subaccount).then(function(data) {
                data.prev_outputs = [];
                for (var i = 0; i < data.prevout_scripts.length; i++) {
                    data.prev_outputs.push(
                        {branch: branches.EXTERNAL, pointer: transaction.pubkey_pointer,
                         subaccount: $scope.wallet.current_subaccount, script: data.prevout_scripts[i]})
                }
                // TODO: verify
                return wallets.sign_and_send_tx($scope, data, true);  // priv_der=true
            }, function(error) {
                gaEvent('Wallet', 'TransactionsTabRedeemFailed', error.args[1]);
                notices.makeNotice('error', error.args[1]);
                return $q.reject(error);
            });
        });
    };
    $scope.redeem = function(transaction) {
        $scope.redeem_transaction = transaction;
        $scope._redeem = function() {
            $scope.redeeming = true;
            _redeem(transaction).then(modal.close).finally(function() {
                $scope.redeeming = false;
            });
        }
        var modal = $uibModal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_tx_redeem.html',
            scope: $scope
        });
    }

    $scope.bump_fee = function(transaction, new_feerate, size_override, level) {
        // copy to avoid adding inputs twice if bump is cancelled:
        transaction = angular.copy(transaction);
        level = level || 0;
        if (level > 10) {
            notices.makeNotice('error', 'Recursion limit exceeded.');
            $scope.bumping_fee = false;
            return $q.reject()
        }
        var ret = $q.defer();

        var txsize = (size_override || transaction.size);
        var new_fee = Math.round(txsize * new_feerate / 1000);
        $scope.bumping_fee = true;
        transaction.bumping_dropdown_open = false;
        var bumpedTx = Bitcoin.contrib.transactionFromHex(transaction.rawtx);
        var targetFeeDelta = new_fee - parseInt(transaction.fee);
        var requiredFeeDelta = (
            txsize + 4 * transaction.inputs.length
        ); // assumes mintxfee = 1000, and inputs increasing
           // by at most 4 bytes per input (signatures have variable lengths)
        var feeDelta = Math.max(targetFeeDelta, requiredFeeDelta);
        var remainingFeeDelta = feeDelta;
        var new_fee = parseInt(transaction.fee) + feeDelta;
        var newOuts = [];
        for (var i = 0; i < transaction.outputs.length; ++i) {
            if (transaction.outputs[i].is_relevant) {
                // either change or re-deposit
                if (bumpedTx.outs[i].value < remainingFeeDelta) {
                    // output too small to be decreased - remove it altogether
                    remainingFeeDelta -= bumpedTx.outs[i].value;
                } else {
                    bumpedTx.outs[i].value -= remainingFeeDelta;
                    remainingFeeDelta = 0;
                    newOuts.push(bumpedTx.outs[i]);
                }
            } else {
                // keep the original non-change output
                newOuts.push(bumpedTx.outs[i]);
            }
        }
        bumpedTx.outs = newOuts;

        var builder = Bitcoin.bitcoin.TransactionBuilder.fromTransaction(
            bumpedTx, cur_net
        );
        // reset hashType to allow adding inputs/outputs
        for (var i = 0; i < builder.inputs.length; ++i) {
            delete builder.inputs[i].hashType;
        }
        function setPrototypeOf (obj, proto) {
          obj.__proto__ = proto
          return obj
        }
        setPrototypeOf = Object.setPrototypeOf || setPrototypeOf
        // (Not really alpha, but we need the same changes allowing signatures
        //  to be deferreds.)
        setPrototypeOf(
            builder,
            Bitcoin.contrib.AlphaTransactionBuilder.prototype
        );

        var builder_d;
        if (remainingFeeDelta > 0) {
            builder_d = tx_sender.call(
                'http://greenaddressit.com/txs/get_all_unspent_outputs',
                1,  // do not include zero-confs (RBF requirement)
                $scope.wallet.current_subaccount
            ).then(function(utxos) {
                var required_utxos = [];
                for (var i = 0; i < utxos.length; ++i) {
                    remainingFeeDelta -= utxos[i].value;
                    required_utxos.push(utxos[i]);
                    if (remainingFeeDelta <= 0) break;
                }
                var change_d = $q.when();
                if (remainingFeeDelta < 0) {
                    // new change output needs to be added
                    change_d = tx_sender.call(
                        'http://greenaddressit.com/vault/fund',
                        $scope.wallet.current_subaccount, true, true
                    ).then(function(data) {
                        return Bitcoin.bitcoin.crypto.hash160(
                            new Bitcoin.Buffer.Buffer(data.script, 'hex')
                        );
                    })
                } else if (remainingFeeDelta == 0) {
                    // if we were lucky enough to match the required value,
                    // no new change output is necessary
                    change_d = $q.when(null);
                } else {   // remainingFeeDelta > 0
                    return $q.reject(gettext("Not enough money"));
                }
                return change_d.then(function(change_hash160) {
                    if (change_hash160) {
                        builder.addOutput(
                            Bitcoin.bitcoin.script.scriptHashOutput(
                                change_hash160
                            ),
                            -remainingFeeDelta
                        );
                    }
                    var utxos_ds = [];
                    for (var i = 0; i < required_utxos.length; ++i) {
                        var requtxo = required_utxos[i];
                        utxos_ds.push(calcRedeemAndKeyPairs(
                            $scope.wallet.current_subaccount,
                            requtxo.pointer
                        ));
                    }
                    return $q.all(utxos_ds).then(function(utxos) {
                        for (var i = 0; i < required_utxos.length; ++i) {
                            var requtxo = required_utxos[i];
                            builder.addInput(
                                [].reverse.call(new Buffer(
                                    requtxo.txhash, 'hex'
                                )),
                                requtxo.pt_idx,
                                0,
                                Bitcoin.bitcoin.script.scriptHashOutput(
                                    Bitcoin.bitcoin.crypto.hash160(
                                        utxos[i].redeemScript
                                    )
                                )
                            )
                        }
                        // add estimated prevscript + signatures + scripts
                        // length (72[prevout] + 74[sig] * 2 for each input)
                        var new_size = builder.tx.byteLength() + builder.tx.ins.length * (72 + 74 * 2);
                        if (Math.round(new_size * new_feerate / 1000) > new_fee) {
                            ret.resolve($scope.bump_fee(
                                transaction, new_feerate, new_size, level + 1
                            ));
                            return;
                        }
                        var requiredFeeDelta = (
                            new_size + 4 * transaction.inputs.length
                        );
                        if (parseInt(transaction.fee) + requiredFeeDelta > new_fee) {
                            ret.resolve($scope.bump_fee(
                                transaction, new_feerate, new_size, level + 1
                            ));
                            return;
                        }
                        // add inputs to transaction.inputs only if it passed
                        // the above checks -- otherwise the recursive call
                        // would have duplicate inputs in transaction.inputs
                        for (var i = 0; i < required_utxos.length; ++i) {
                            var requtxo = required_utxos[i];
                            transaction.inputs.push(
                                {pubkey_pointer: requtxo.pointer}
                            );
                        }
                        return builder;
                    });
                })
            });
        } else {
            builder_d = $q.when(builder);
        }

        builder_d.then(function(builder) {
            if (!builder) return;  // recursive call to bump_fee above

            var modal_d = wallets.ask_for_tx_confirmation(
                $scope, builder.tx,
                {fee: parseInt(transaction.fee) + feeDelta,
                 bumped_tx: transaction,
                 recipient: transaction.description_short}
            );

            var prev_outputs = [];
            for (var i = 0; i < transaction.inputs.length; ++i) {
                (function(utxo) {
                    prev_outputs.push(calcRedeemAndKeyPairs(
                        $scope.wallet.current_subaccount,
                        utxo.pubkey_pointer
                    ).then(function(res) {
                        return {
                            branch: branches.REGULAR,
                            subaccount: $scope.wallet.current_subaccount,
                            pointer: utxo.pubkey_pointer,
                            script: res.redeemScript.toString('hex')
                        }
                    }));
                })(transaction.inputs[i]);
            }

            var prevouts_rawtxs = {};
            var prevouts_rawtxs_ds = $q.all(
                builder.tx.ins.map(function(inp) {
                    var reversed_hex = Bitcoin.bitcoin.bufferutils.reverse(
                        inp.hash
                    ).toString('hex');
                    return tx_sender.call(
                        'http://greenaddressit.com/txs/get_raw_unspent_output',
                        reversed_hex
                    ).then(function(rawtx) {
                        prevouts_rawtxs[reversed_hex] = rawtx;
                    });
                })
            );

            var signatures_d = $q.all(prev_outputs).then(function(res) {
                var txdata = {
                    prev_outputs: res
                };
                return prevouts_rawtxs_ds.then(function() {
                    return wallets.sign_tx(
                        $scope, builder.tx, txdata, {data: prevouts_rawtxs}, function (progress) {}
                    );
                })

            });

            var signatures_and_modal = modal_d.then(function() {
                return signatures_d.then(function(signatures) {
                    return signatures.concat([modal_d]);
                });
            });

            ret.resolve(signatures_and_modal.then(function(results) {
                var try_sending = function(twofac_data) {
                    for (var i = 0; i < transaction.inputs.length; ++i) {
                        builder.inputs[i].signatures = [
                            null,
                            Bitcoin.bitcoin.ECSignature.fromDER(
                                new Bitcoin.Buffer.Buffer(results[i].substr(
                                    0, results[i].length-2 // strip hashType
                                ), 'hex')
                            )
                        ];
                        builder.inputs[i].hashType = 1;
                    }
                    return tx_sender.call(
                        'http://greenaddressit.com/vault/send_raw_tx',
                        builder.build().toHex(), twofac_data
                    ).then(function(data) {
                        if (data.limit_decrease) {
                            $scope.wallet.limits.total -= data.limit_decrease;
                        }
                    });
                }

                // try without 2FA to see if it's required
                // (could be bump amount under the user-defined 2FA threshold)
                return try_sending({
                    'try_under_limits_bump': feeDelta
                }).catch(function(e) {
                    if (e.args && e.args[0] &&
                            e.args[0] == "http://greenaddressit.com/error#auth") {
                        return wallets.get_two_factor_code(
                            $scope, 'bump_fee', {amount: feeDelta}
                        ).then(function(twofac_data) {
                            twofac_data.bump_fee_amount = feeDelta;
                            return try_sending(twofac_data);
                        });
                    } else {
                        return $q.reject(e);
                    }
                });
            }).catch(function(e) {
                notices.makeNotice('error', e.args ? e.args[1] : e);
            }).finally(function() {
                $scope.bumping_fee = false;
            }));
        }).catch(function(e) {
            $scope.bumping_fee = false;
            notices.makeNotice('error', e.args ? e.args[1] : e);
        });
        return ret;
    };

    $scope.edit_tx_memo = function(tx) {
        if (tx.new_memo == tx.memo) {
            // nothing to do
            tx.changing_memo = false;
        } else {
            tx_sender.call('http://greenaddressit.com/txs/change_memo', tx.txhash, tx.new_memo).then(function() {
                tx.memo = tx.new_memo;
                tx.changing_memo = false;
            }, function(err) {
                notices.makeNotice('error', err.args[1]);
            });
        }
    };

    $scope.start_editing_tx_memo = function(tx) {
        tx.changing_memo = true;
        tx.new_memo = tx.memo;
    };

    $scope.details = function(transaction) {
        gaEvent('Wallet', 'TransactionsTabDetailsModal');
        $scope.selected_transaction = transaction;
        var current_estimate = 25, best_estimate;
        var keys = Object.keys($scope.wallet.fee_estimates).sort();
        for (var i = 0; i < keys.length; ++i) {
            var estimate = $scope.wallet.fee_estimates[keys[i]];
            if (i == 0) best_estimate = estimate.blocks;
            var feerate = estimate.feerate * 1000*1000*100;
            var estimated_fee = Math.round(
                feerate * transaction.size / 1000
            );
            // If cur fee is already above estimated, don't suggest it.
            // Needs to be checked early to avoid suggesting the minimum of
            // tx.fee + tx.size needlessly.
            if (parseInt(transaction.fee) >= estimated_fee) {
                current_estimate = estimate.blocks
                break;
            }
        }
        transaction.current_estimate = current_estimate;
        if (transaction.has_payment_request && !transaction.payment_request) {
            tx_sender.call('http://greenaddressit.com/txs/get_payment_request', transaction.txhash).then(function(payreq_b64) {
                transaction.payment_request = 'data:application/bitcoin-paymentrequest;base64,' + payreq_b64;
            });
        }
        $uibModal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_tx_details.html',
            scope: $scope
        })
    };

    $scope.show_voucher = function(transaction, passphrase) {
        return $q.when($scope.wallet.hdwallet.deriveHardened(branches.EXTERNAL)).then(function(key) {
            return $q.when(key.deriveHardened(transaction.pubkey_pointer)).then(function(key) {
                return encode_key(key, passphrase).then(function(enckey) {
                    $scope.voucher = {
                        encrypted: !!passphrase,
                        enckey: enckey,
                        satoshis: transaction.social_value,
                        url: 'https://' + hostname + '/redeem/?amount=' + transaction.social_value + '#/redeem/' + enckey,
                        text: transaction.social_destination.text
                    };
                    $uibModal.open({
                        templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_voucher.html',
                        scope: $scope
                    });
                });
            });
        });
    };

    $scope.show_encrypted_voucher = function(transaction) {
        $scope.encrypting_voucher = true;
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
                var that = this;
                this.encrypting = true;
                $scope.show_voucher(transaction, this.password).then(function() {
                    that.encrypting = false;
                    modal.close();
                });
            }
        }
        var modal = $uibModal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signuplogin/modal_encryption_password.html',
            scope: $scope
        });
    };

    $scope.toggle_transaction_search = function() {
        $scope.search_visible = !$scope.search_visible;
    }


}]);
