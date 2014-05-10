var deps = ['greenWalletBaseApp', 'ngRoute', 'ui.bootstrap', 'greenWalletDirectives', 'greenWalletControllers',
     'greenWalletInfoControllers', 'greenWalletSettingsControllers', 'greenWalletTransactionsControllers',
     'greenWalletReceiveControllers', 'greenWalletSendControllers', 'greenWalletSignupLoginControllers', 'ja.qr'];
if (window.cordova) {
    deps.push('greenWalletNFCControllers');
    localStorage.hasWallet = true;  // enables redirect to wallet from front page (see js/greenaddress.js)
}
var greenWalletApp = angular.module('greenWalletApp', deps)
.controller('SignupController', ['$scope', '$injector', '$controller', function($scope, $injector, $controller) {
    $script(BASE_URL+'/static/js/signup.min.js', function() {
        // injector method takes an array of modules as the first argument
        // if you want your controller to be able to use components from
        // any of your other modules, make sure you include it together with 'ng'
        // Furthermore we need to pass on the $scope as it's unique to this controller
        $injector.invoke(SignupControllerAsync, this, {'$scope': $scope});
    });
}])
.constant('branches', {
	REGULAR: 1,
    EXTERNAL: 2
})
.config(['$routeProvider', '$provide', function config($routeProvider, $provide) {
    $routeProvider
        .when('/', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signuplogin/base.html',
            controller: 'SignupLoginController'
        })
        .when('/info', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_info.html',
            controller: 'InfoController'
        })
        .when('/transactions', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_transactions.html',
            controller: 'TransactionsController'
        })
        .when('/receive', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_receive.html',
            controller: 'ReceiveController'
        })
        .when('/send', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_send.html',
            controller: 'SendController'
        })
        .when('/send/:contact', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_send.html',
            controller: 'SendController'
        })
        .when('/address-book', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_address_book.html'
            //controller: 'SettingsController'
        })
        .when('/address-book/name_:name', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_address_book.html'
            //controller: 'SettingsController'
        })
        .when('/address-book/:page', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_address_book.html'
            //controller: 'SettingsController'
        })
        .when('/settings', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_settings.html',
            controller: 'SettingsController'
        })
        .when('/create_warning', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signup_0_warning.html',
            controller: 'SignupController'
        })
        .when('/create', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signup_1_init.html',
            controller: 'SignupController'
        })
        .when('/signup_pin', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signup_2_pin.html',
            controller: 'SignupController'
        })
        .when('/signup_oauth', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signup_3_oauth.html',
            controller: 'SignupController'
        })
        .when('/signup_2factor', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/signup_4_2factor.html',
            controller: 'SignupController'
        })
        .when('/concurrent_login', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/concurrent_login.html',
            controller: 'SignupController'
        })
        .when('/browser_unsupported', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/browser_unsupported.html'
        })
        .when('/redeem/:enckey', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_info.html',
            controller: 'InfoController'
        })
        .when('/pay/:pay_receiver', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_info.html',
            controller: 'InfoController'
        })
        .when('/uri/', {
            templateUrl: BASE_URL+'/'+LANG+'/wallet/partials/wallet_info.html',
            controller: 'InfoController'
        });
        
}]).run(['$rootScope', function($rootScope, $location) {
    $rootScope.$location = $location;
}]).factory("backButtonHandler", function () {
    var backButtonHandlerService = {
        handlers: [],
        exitAppHandler: function() {
            navigator.app.exitApp();
        },
        pushHandler: function(handler) {
            if (this.handlers.length) {
                document.removeEventListener("backbutton", this.handlers[this.handlers.length-1]);
            }
            this.handlers.push(handler);
            document.addEventListener("backbutton", handler);
        },
        popHandler: function() {
            document.removeEventListener("backbutton", this.handlers.pop());
            if (this.handlers.length) {
                document.addEventListener("backbutton", this.handlers[this.handlers.length-1]);
            }
        }
    };
    return backButtonHandlerService;
}).directive("toggleableMenu", ['$location', 'cordovaReady', 'backButtonHandler',
        function($location, cordovaReady, backButtonHandler) {
    return {
        restrict: 'A',
        controller: ['$scope', function($scope) {
            var state = false;
            if (window.cordova) {
                var backHandler = function() {
                    $scope.toggle_set(false);
                };
                cordovaReady(function() {
                    document.addEventListener("menubutton", function() {
                        $scope.toggle_set(true);
                    });
                })();
            }
            var toggleClasses = [];
            this.registerToggleClass = function(element, cls) {
                toggleClasses.push([element, cls]);
            };
            $scope.toggle_set = function(enable) {
                if (state == enable) return;
                state = enable;
                for (var i = 0 ; i < toggleClasses.length; ++i) {
                    var tc = toggleClasses[i];
                    if (enable) {
                        tc[0].addClass(tc[1]);
                    } else {
                        tc[0].removeClass(tc[1]);
                    }
                }
                if (window.cordova) {
                    if (state) {
                        backButtonHandler.pushHandler(backHandler);
                    } else {
                        backButtonHandler.popHandler();
                    }
                }
            };
        }],
        link: function(scope, element, attrs) {
            element.find('a').on('click', function() {
                var a = angular.element(this);
                scope.toggle_set(false);
            });
            scope.$watch(function() { return $location.path(); },
                function(newValue, oldValue) {
                    var all_a = element.find('a');
                    for (var i = 0; i < all_a.length; i++) {
                        var a = angular.element(all_a[i]);
                        if (newValue.indexOf(a.parent().attr('path')) != -1) {
                            scope.subpage_title = a.text();
                            a.parent().addClass('selected');
                        } else {
                            a.parent().removeClass('selected');
                        }
                    }
                });
        }
    };
}]).directive("toggleClass", function() {
    return {
        restrict: 'A',
        require: '^toggleableMenu',
        link: function(scope, element, attrs, toggleableMenuController) {
            toggleableMenuController.registerToggleClass(element, attrs['toggleClass']);
        }
    };
});
