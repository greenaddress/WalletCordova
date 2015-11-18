var deps = ['ngAnimate'];
if(/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent)) {
   deps.push('ngTouch');
}
angular.module('instantVerificationApp', deps)
.config(['$interpolateProvider', '$httpProvider',
        function config($interpolateProvider, $httpProvider) {
    // don't conflict with Django templates
    $interpolateProvider.startSymbol('((');
    $interpolateProvider.endSymbol('))');

    // show loading indicator on http requests
    /*
    $httpProvider.interceptors.push(['$q', '$rootScope', '$timeout', 'notices',
            function($q, $rootScope, $timeout, notices) {
        return {
            'request': function(config) {
                if (config.no_loading_indicator) return config || $q.when(config);
                if (!$rootScope.is_loading) $rootScope.is_loading = 0;
                notices.setLoadingText('Loading', true);  // for requests without setLoadingText
                $rootScope.is_loading += 1;
                return config || $q.when(config);
            },
            'response': function(response) {
                if (response.config.no_loading_indicator) return response || $q.when(response);
                if (!$rootScope.is_loading) $rootScope.is_loading = 1;
                $rootScope.is_loading -= 1;
                notices.setLoadingText();  // clear it (it's one-off)
                return response || $q.when(response);
            },
            'responseError': function(rejection) {
                if (!$rootScope.is_loading) $rootScope.is_loading = 1;
                $rootScope.is_loading -= 1;
                notices.setLoadingText();  // clear it (it's one-off)
                return $q.reject(rejection);
            }
        };
    }]);

    $httpProvider.defaults.xsrfCookieName = 'csrftoken';
    $httpProvider.defaults.xsrfHeaderName = 'x-csrftoken'; */
}])
.controller('VerifyInstantController', ['$scope', '$http', function($scope, $http) {
    $scope.verification = {};
    $scope.verify = function() {
        $scope.verification.verifying = true;
        if ($scope.verification.signature) {
            var signature = $scope.verification.signature;
        } else {
            var message = 'Please verify if ' + $scope.verification.txhash + ' is GreenAddress instant confirmed';
            try {
                var key = new Bitcoin.ECKey($scope.verification.wif_privkey);
            } catch(e) {
                $scope.verification.error = gettext('Invalid WIF key');
                $scope.verification.verifying = false;
                return;
            }
            var signature = Bitcoin.Message.sign(key, message, cur_net);
            signature = Bitcoin.convert.bytesToWordArray(signature);
            signature = Bitcoin.CryptoJS.enc.Base64.stringify(signature);
        }

        $http.get((window.root_url||'')+'/verify/', {params: 
            {txhash: $scope.verification.txhash, signature: signature}
        }).then(function(response) {
            if (response.data.verified) {
                $scope.verification.result = 'success';
            } else {
                $scope.verification.result = 'failure';
            }
        }).finally(function() { $scope.verification.verifying = false; });
    };
    $scope.try_again = function() {
        $scope.verification = {};
    };
}]);