angular.module('greenWalletInfoControllers',
    ['greenWalletServices'])
.controller('InfoController', ['$scope', 'wallets', 'tx_sender', '$modal', '$q', 'notices', '$location', 'gaEvent', 'cordovaReady',
        function InfoController($scope, wallets, tx_sender, $modal, $q, notices, $location, gaEvent, cordovaReady) {
    if(!wallets.requireWallet($scope)) return;
    
    $scope.wallet.hidden = false;
    if ($scope.wallet.signup) {
        gaEvent('Signup', 'OpenedWallet');
        $scope.wallet.signup = false;
    }

    $scope.wallet.has_graph = true;  // element needs to be initially visible to allow computing width
    var update_graph = function() {
        var btcGraph = dc.lineChart("#btc_graph");
        var prevDate;
        var balance = parseInt($scope.wallet.final_balance), balances_arr = [];
        var bMin = balance, bMax = balance;
        if ($scope.wallet.transactions) {
            for(var i = 0; i < $scope.wallet.transactions.list.length; i++) {
                var tx = $scope.wallet.transactions.list[i];
                var curDate = tx.ts;
                if (i == 0 || (prevDate - curDate) / 1000 > 3600) {
                    balances_arr.unshift({date: curDate, balance: balance});
                    bMin = Math.min(bMin, balance); bMax = Math.max(bMax, balance);
                    prevDate = curDate;
                }
                balance -= parseInt(tx.value);
            }
        }
        if (balances_arr.length < 2) {
            balances_arr = [{date: new Date(), balance: 0}];
            $scope.wallet.has_graph = false;
            gaEvent('Wallet', 'NotEnoughTxForBalanceGraph');
        } else {
            $scope.wallet.has_graph = true;
        }
        var balances = crossfilter(balances_arr);
        var byDate = balances.dimension(function(d) {return d.date} );
        var getSize = function() {
            var parent = document.getElementById('btc_graph').parentNode;
            return [Math.round(parent.offsetWidth), Math.round(parent.offsetWidth * (290/920))];
        };
        var size = getSize();
        var pow = {'BTC': 8, 'mBTC': 5, 'µBTC': 2}[$scope.wallet.unit];
        bMin /= Math.pow(10, pow); bMax /= Math.pow(10, pow);
        var dScale = (bMax - bMin) * 0.1;
        btcGraph.width(size[0]).height(size[1])
            .colors(['#69b16e'])
            .margins({top: 10, right: 50, bottom: 30, left: 60})
            .dimension(byDate)
            .valueAccessor(function (p) {
                return p.value / Math.pow(10, pow);
            })
            .group(byDate.group().reduceSum(function(p) { return p.balance; }))
            .x(d3.time.scale().domain([balances_arr[0].date, balances_arr[balances_arr.length-1].date]))
            .y(d3.scale.linear().domain([Math.max(0, bMin-dScale), bMax+dScale]))
            .brushOn(false)
            .renderlet(
                function(chart) {
                    chart.select("svg").attr("viewBox",
                            "0 0 " + size[0] + " " + size[1]).attr("preserveAspectRatio", "xMidYMid")
                    if (!$scope.wallet.has_graph) {
                        var text = chart.select("svg").selectAll("text").data(['empty']).enter().append("text");
                        text.attr("x", size[0]/2)
                            .attr("y", size[1]/2)
                            .attr("text-anchor", "middle")
                            .text(gettext("Not enough data to draw the graph"));
                    }
                });
        btcGraph.xAxis().ticks(Math.floor(size[0]/100));
        btcGraph.yAxis().ticks(Math.floor(size[1]/30));
        dc.renderAll();
        angular.element(window).on('resize', function() {
            var size = getSize();
            var svg = document.getElementById('btc_graph').getElementsByTagName('svg')[0];
            svg.setAttribute("width", size[0]);
            svg.setAttribute("height", size[1]);
        });
        gaEvent('Wallet', 'BalanceGraphShown');
    }

    $scope.$watch('wallet.transactions', function(newValue, oldValue) {
        if (!$scope.wallet.transactions) { update_graph(); return; }
        $scope.wallet.transactions.limit = 10;
        $scope.wallet.transactions.populate_csv();
        if ($scope.wallet.transactions.list.length) update_graph();
    });

    var redeem = function(encrypted_key, password) {
        var deferred = $q.defer()
        var errors = {
            invalid_privkey: gettext('Not a valid encrypted private key'),
            invalid_unenc_privkey: gettext('Not a valid private key'),
            invalid_passphrase: gettext('Invalid passphrase')
        }
        var sweep = function(key_bytes) {
            var key = new Bitcoin.ECKey(key_bytes);
            tx_sender.call("http://greenaddressit.com/vault/prepare_sweep_social", key.getPubCompressed()).then(function(data) {
                data.prev_outputs = [];
                for (var i = 0; i < data.prevout_scripts.length; i++) {
                    data.prev_outputs.push(
                        {privkey: key, script: data.prevout_scripts[i]})
                }
                // TODO: verify
                wallets.sign_and_send_tx(undefined, data, false, null, gettext('Funds redeemed'));
            }, function(error) {
                if (error.uri == 'http://greenaddressit.com/error#notenoughmoney') {
                    notices.makeNotice('error', gettext('Already redeemed'));
                } else {
                    notices.makeNotice('error', error.desc);
                }
            });
        };
        if (encrypted_key.indexOf('K') == 0 || encrypted_key.indexOf('L') == 0 || encrypted_key.indexOf('c') == 0) {  // unencrypted
            var bytes = B58.decode(encrypted_key);
            if (bytes.length != 38) {
                deferred.reject(errors.invalid_unenc_privkey);
                return deferred.promise;
            }
            var expChecksum = bytes.slice(-4);
            bytes = bytes.slice(0, -4);
            var checksum = Crypto.SHA256(Crypto.SHA256(bytes, {asBytes: true}), {asBytes: true});
            if (checksum[0] != expChecksum[0] || checksum[1] != expChecksum[1] || checksum[2] != expChecksum[2] || checksum[3] != expChecksum[3]) {
                deferred.reject(errors.invalid_unenc_privkey);
                return deferred.promise;
            }
            if (cur_coin == 'BTT') {
                var version = 0xef;
            } else {
                var version = 0x80;
            }
            if (bytes[0] != version) {
                deferred.reject(errors.invalid_unenc_privkey);
                return deferred.promise;
            }
            bytes = bytes.slice(1, -1);
            sweep(bytes);
            deferred.resolve();
        } else {
            if (window.cordova) {
                cordovaReady(function() {
                    cordova.exec(function(data) {
                        $scope.$apply(function() {
                            sweep(data);
                            deferred.resolve();
                        });
                    }, function(fail) {
                        deferred.reject([fail == 'invalid_passphrase', errors[fail] || fail]);
                    }, "BIP38", "decrypt", [encrypted_key, password, cur_coin]);
                })();
            } else {
                var worker = new Worker("/static/js/bip38_worker.min.js");
                worker.onmessage = function(message) {
                    if (message.data.error) {
                        deferred.reject([message.data.error == 'invalid_passphrase',
                                         errors[message.data.error]]);
                    } else {
                        sweep(message.data);
                        deferred.resolve();
                    }
                }
                worker.postMessage({data: encrypted_key,
                                    key: password,
                                    cur_coin_version: cur_coin_version});
            }
        }
        return deferred.promise;
    };

    if ($scope.wallet.redeem_key && !$scope.wallet.redeem_closed) {
        if ($scope.wallet.redeem_key.indexOf('K') == 0 || $scope.wallet.redeem_key.indexOf('L') == 0 || $scope.wallet.redeem_key.indexOf('c') == 0) {  // unencrypted
            redeem($scope.wallet.redeem_key).then(function() {
                gaEvent('Wallet', 'SocialRedeemSuccessful');
            }, function(e) {
                gaEvent('Wallet', 'SocialRedeemError', e);
                notices.makeNotice('error', e);
            })
        } else {
            $scope.redeem_modal = {
                redeem: function() {
                    var that = this;
                    this.decrypting = true;
                    this.error = undefined;
                    redeem($scope.wallet.redeem_key, this.password).then(function() {
                        gaEvent('Wallet', 'SocialRedeemSuccessful');
                        modal.close();
                    }, function(e) {
                        gaEvent('Wallet', 'SocialRedeemError', e[1]);
                        that.decrypting = false;
                        if (e[0]) that.error = e[1];
                        else {
                            modal.dismiss();
                            notices.makeNotice('error', e[1]);
                        }
                    })
                }
            };
        
            var modal = $modal.open({
                templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signuplogin/redeem_password_modal.html',
                scope: $scope
            });
            gaEvent('Wallet', 'SocialRedeemModal');
            modal.result.finally(function() {
                // don't show the modal twice
                $scope.wallet.redeem_closed = true;
            });
        }
        $scope.redeem_shown = true;
    }

    if ($scope.wallet.send_to_receiving_id && !$scope.wallet.send_to_receiving_id_shown) {
        gaEvent('Wallet', 'SendToReceivingId');
        $scope.wallet.send_to_receiving_id_shown = true;
        var receiving_id = $scope.wallet.send_to_receiving_id;
        var recipient = {name: receiving_id, address: receiving_id, type: receiving_id.indexOf('reddit:') == -1 ? 'address' : 'reddit',
                         amount: $scope.wallet.send_to_receiving_id_amount};
        $location.path('/send/' + Crypto.util.bytesToBase64(UTF8.stringToBytes(JSON.stringify(recipient))));
    }
}]);
