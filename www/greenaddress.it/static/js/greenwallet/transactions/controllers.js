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
                return key.derivePrivate(branches.SUBACCOUNT);
            }).then(function(key) {
                return key.derivePrivate($scope.wallet.current_subaccount);
            })
        }
        key = key.then(function(key) {
            return key.derivePrivate(branches.EXTERNAL);
        }).then(function(key) {
            return key.derivePrivate(transaction.pubkey_pointer);
        });
        return key.then(function(key) {
            return tx_sender.call("http://greenaddressit.com/vault/prepare_sweep_social",
                    key.pub.toBytes(), false, $scope.wallet.current_subaccount).then(function(data) {
                data.prev_outputs = [];
                for (var i = 0; i < data.prevout_scripts.length; i++) {
                    data.prev_outputs.push(
                        {branch: branches.EXTERNAL, pointer: transaction.pubkey_pointer,
                         subaccount: $scope.wallet.current_subaccount, script: data.prevout_scripts[i]})
                }
                // TODO: verify
                return wallets.sign_and_send_tx(undefined, data, true);  // priv_der=true
            }, function(error) {
                gaEvent('Wallet', 'TransactionsTabRedeemFailed', error.desc);
                notices.makeNotice('error', error.desc);
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

    $scope.edit_tx_memo = function(tx) {
        if (tx.new_memo == tx.memo) {
            // nothing to do
            tx.changing_memo = false;
        } else {
            tx_sender.call('http://greenaddressit.com/txs/change_memo', tx.txhash, tx.new_memo).then(function() {
                tx.memo = tx.new_memo;
                tx.changing_memo = false;
            }, function(err) {
                notices.makeNotice('error', err.desc);
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
        return $q.when($scope.wallet.hdwallet.derivePrivate(branches.EXTERNAL)).then(function(key) {
            return $q.when(key.derivePrivate(transaction.pubkey_pointer)).then(function(key) {
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
