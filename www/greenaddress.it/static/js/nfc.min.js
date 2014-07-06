angular.module('greenWalletNFCControllers', ['greenWalletServices'])
.controller('NFCController', ['$rootScope', '$scope', '$modalInstance', 'cordovaReady', 'notices',
        function NFCController($rootScope, $scope, $modalInstance, cordovaReady, notices) {
    $scope.nfc_init_error = false;
    $scope.nfc_init_succeeded = 0;
    cordovaReady(function() {
        var writeTag = function(nfcEvent) {
            var record = ndef.mimeMediaRecord($scope.nfc_mime, $scope.nfc_bytes);
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
        
        nfc.removeMimeTypeListener('x-ga/en', commonNFCXGaitMNCListener, undefined);
        nfc.removeMimeTypeListener('x-gait/mnc', commonNFCXGaitMNCListener, undefined);

        nfc.addTagDiscoveredListener(writeTag, win, fail);
        nfc.addMimeTypeListener('x-gait/mnc', writeTag, win, fail); // overwrite
        nfc.addMimeTypeListener('x-ga/en', writeTag, win, fail); // overwrite
        nfc.addNdefFormatableListener(formatTag, win, fail);
        
        $modalInstance.result.finally(function() {
            // TODO: also suspend/resume?
            var removeFail = function() {
                $rootScope.safeApply(function() {
                    // notices.makeNotice('error', gettext('Failed removing NFC listener'));
                    console.log('Failed removing NFC listener');
                });
            };
            nfc.removeTagDiscoveredListener(writeTag, undefined, removeFail);
            document.removeEventListener("ndef-formatable", formatTag, false);
            // re-add the original mime listener
            nfc.removeMimeTypeListener('x-ga/en', writeTag, undefined, removeFail);
            nfc.removeMimeTypeListener('x-gait/mnc', writeTag, undefined, removeFail);

            nfc.addMimeTypeListener('x-ga/en', commonNFCXGaitMNCListener);
            nfc.addMimeTypeListener('x-gait/mnc', commonNFCXGaitMNCListener);
        });
    })();
}]);
