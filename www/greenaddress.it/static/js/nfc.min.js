angular.module('greenWalletNFCControllers', ['greenWalletServices'])
.controller('NFCController', ['$rootScope', '$scope', '$modalInstance', 'cordovaReady', 'notices', 'mnemonics',
        function NFCController($rootScope, $scope, $modalInstance, cordovaReady, notices, mnemonics) {
    $scope.nfc_init_error = false;
    $scope.nfc_init_succeeded = 0;
    mnemonics.getMnemonicMap();   // should make validateMnemonic work instantly inside writeTag
    cordovaReady(function() {
        var writeTag = function(nfcEvent) {
            mnemonics.validateMnemonic($scope.wallet.mnemonic).then(function(bytes) {
                var record = ndef.mimeMediaRecord('x-gait/mnc', bytes);
                nfc.write([record], function() {
                    $scope.$apply(function() {
                        $scope.num_tags_written += 1;
                        $scope.nfc_error = false;
                    });
                }, function(reason) {
                    $scope.$apply(function() {
                        $scope.nfc_error = {reason: reason};
                    });
                });
            });
        };
        var win = function() {
            $rootScope.safeApply(function() {
                $scope.nfc_init_succeeded += 1;
                $scope.num_tags_written = 0;
                $scope.num_tags_formatted = 0;
            });
        };
        var fail = function() {
            $rootScope.safeApply(function() {
                $scope.nfc_init_error = true;
            });
        };
        var formatTag = function() {
            nfc.erase(function() {
                $scope.$apply(function() {
                    $scope.num_tags_formatted += 1;
                    $scope.nfc_error = false;
                });
            }, function(reason) {
                $scope.$apply(function() {
                    $scope.nfc_error = {reason: reason};
                });
            });
        }
        nfc.removeMimeTypeListener('x-gait/mnc', commonNFCXGaitMNCListener, function() {
            nfc.addTagDiscoveredListener(writeTag, win, fail);
            nfc.addMimeTypeListener('x-gait/mnc', writeTag, win, fail); // overwrite
            nfc.addNdefFormatableListener(formatTag, win, fail);
        }, fail);
        $modalInstance.result.finally(function() {
            // TODO: also suspend/resume?
            nfc.removeTagDiscoveredListener(writeTag, undefined, function() {
                $rootScope.safeApply(function() {
                    notices.makeNotice('error', gettext('Failed removing NFC listener'));
                });
            });
            document.removeEventListener("ndef-formatable", formatTag, false);
            // re-add the original mime listener
            nfc.removeMimeTypeListener('x-gait/mnc', writeTag, function() {
                nfc.addMimeTypeListener('x-gait/mnc', commonNFCXGaitMNCListener);
            });
        });
    })();
}]);
