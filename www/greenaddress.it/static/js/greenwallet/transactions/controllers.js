angular.module('greenWalletTransactionsControllers',
    ['greenWalletServices'])
.controller('TransactionsController', ['$scope', 'wallets', 'tx_sender', 'notices', 'branches', '$modal', 'gaEvent', '$timeout', '$q', 'encode_key', 'hostname',
        function TransactionsController($scope, wallets, tx_sender, notices, branches, $modal, gaEvent, $timeout, $q, encode_key, hostname) {
    // required already by InfoController
    // if(!wallets.requireWallet($scope)) return;

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
        var modal = $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_modal_tx_redeem.html',
            scope: $scope
        });
    }

    $scope.bump_fee = function(transaction, new_fee) {
        new_fee = Math.round(new_fee);
        $scope.bumping_fee = true;
        transaction.bumping_dropdown_open = false;
        //tx_sender.call(
        //              'http://greenaddressit.com/txs/get_all_unspent_outputs',
        //            1   // do not include zero-confs
        //      ).then(function(utxos) {
        var bumpedTx = Bitcoin.contrib.transactionFromHex(transaction.rawtx);
        var targetFeeDelta = new_fee - parseInt(transaction.fee);
        var requiredFeeDelta = transaction.rawtx.length / 2; // assumes mintxfee = 1000
        var feeDelta = Math.max(targetFeeDelta, requiredFeeDelta);
        var remainingFeeDelta = feeDelta;
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

        if (remainingFeeDelta > 0) {
            notices.makeNotice('error', 'Adding inputs not yet supported');
            return;
        }

        var builder = Bitcoin.bitcoin.TransactionBuilder.fromTransaction(
            bumpedTx, cur_net
        );
        // (Not really alpha, but we need the same changes allowing signatures
        //  to be deferreds.)
        Object.setPrototypeOf(
            builder,
            Bitcoin.contrib.AlphaTransactionBuilder.prototype
        );

        var signatures_ds = [];
        for (var i = 0; i < transaction.inputs.length; ++i) {
            (function (i) {
                var utxo = transaction.inputs[i];
                var gawallet = new Bitcoin.bitcoin.HDNode(
                    Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(
                        new Bitcoin.Buffer.Buffer(deposit_pubkey, 'hex'),
                        cur_net
                    ),
                    new Bitcoin.Buffer.Buffer(deposit_chaincode, 'hex')
                );
                var gaKey;
                if ($scope.wallet.current_subaccount) {
                    gaKey = gawallet.derive(3).then(function (branch) {
                        return branch.subpath($scope.wallet.gait_path);
                    }).then(function (gawallet) {
                        return gawallet.derive($scope.wallet.current_subaccount);
                    });
                } else {
                    gaKey = gawallet.derive(1).then(function (branch) {
                        return branch.subpath($scope.wallet.gait_path);
                    });
                }
                gaKey = gaKey.then(function (gawallet) {
                    return gawallet.derive(utxo.pubkey_pointer);
                });
                var userKey = $q.when($scope.wallet.hdwallet);
                if ($scope.wallet.current_subaccount) {
                    userKey = userKey.then(function (key) {
                        return key.deriveHardened(branches.SUBACCOUNT);
                    }).then(function (key) {
                        return key.deriveHardened($scope.wallet.current_subaccount);
                    })
                }
                var userKey = userKey.then(function (key) {
                    return key.derive(branches.REGULAR);
                }).then(function (branch) {
                    return branch.derive(utxo.pubkey_pointer)
                });
                signatures_ds.push($q.all([gaKey, userKey]).then(function (keys) {
                    var gaKey = keys[0], userKey = keys[1];
                    var redeemScript = Bitcoin.bitcoin.script.multisigOutput(
                        2,
                        [gaKey.keyPair.getPublicKeyBuffer(),
                         userKey.keyPair.getPublicKeyBuffer()]
                    )
                    builder.inputs[i].signatures = [];
                    return builder.sign(i, userKey.keyPair, redeemScript);
                }));
            })(i);
        }

        var modal_d = wallets.ask_for_tx_confirmation(
            $scope, builder.tx,
            {fee: parseInt(transaction.fee) + feeDelta,
             bumped_tx: transaction,
             recipient: transaction.description_short}
        );

        return $q.all(signatures_ds.concat([modal_d])).then(function(results) {
            var try_sending = function(twofac_data) {
                return tx_sender.call(
                    'http://greenaddressit.com/vault/send_raw_tx',
                    builder.build().toHex(), twofac_data
                );
            }
            // try without 2FA to see if it's required
            // (could be bump amount under the user-defined 2FA threshold)
            return try_sending().catch(function(e) {
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
        });
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
        if (transaction.has_payment_request && !transaction.payment_request) {
            tx_sender.call('http://greenaddressit.com/txs/get_payment_request', transaction.txhash).then(function(payreq_b64) {
                transaction.payment_request = 'data:application/bitcoin-paymentrequest;base64,' + payreq_b64;
            });
        }
        $modal.open({
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
                    $modal.open({
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
        var modal = $modal.open({
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signuplogin/modal_encryption_password.html',
            scope: $scope
        });
    };

    $scope.toggle_transaction_search = function() {
        $scope.search_visible = !$scope.search_visible;
    }


}]);
