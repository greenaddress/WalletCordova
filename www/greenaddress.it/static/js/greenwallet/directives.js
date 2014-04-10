angular.module('greenWalletDirectives', [])
.directive('maskInput', function() {
    // should be used with class="pin" or otherwise something that sets webkitTextSecurity
    return {
        link: function(scope, element) {
            var style = window.getComputedStyle(element[0]);
            if(style.webkitTextSecurity) {
                // do nothing
            } else {
                // Firefox doesn't support -webkit-text-security
                element[0].setAttribute("type", "password");
            }
        }
    };
}).directive('submitter', function() {
    return {
        require: '^submittable',
        link: function(scope, element, attrs, submittableCtrl) { submittableCtrl.setSubmitter(element); }
    };
}).directive('clickfix', function() {
    return {
        link: function(scope, element, attrs) {
            element.on('touchstart', function(event) {
                event.stopPropagation();
                var clickEvent = document.createEvent('MouseEvent');
                clickEvent.initEvent('click', true, true);
                element[0].dispatchEvent(clickEvent);
            });
        }
    };
}).directive('submitterScope', function() {
    // used by getTemplate() in settings/directives.js
    return {
        link: function(scope, element, attrs) { scope.submittableCtrl.setSubmitter(element); }
    };
}).directive('submittable', function() {
    return {
        scope: true,
        controller: ['$scope', '$timeout', function SubmittableController($scope, $timeout) {
            var submitter;
            this.setSubmitter = function(newSubmitter) { submitter = newSubmitter; }
            $scope.submit_me = function() { $timeout(function(){
                var clickEvent = document.createEvent('MouseEvent');
                clickEvent.initEvent('click', true, true);
                submitter[0].dispatchEvent(clickEvent);
            }); }
        }],
        link: function($scope, elem) {
            elem.find('input').on('invalid', function() {
                $scope.safeApply(function() { if($scope.state) $scope.state.error = true; });
            });
        }
    };
}).directive('focusOn', ['$timeout', function($timeout) {
    return function(scope, elem, attr) {
        scope.$on('focusOn', function(e, name) {
            if(name === attr.focusOn) {
                $timeout(function() { elem[0].focus(); });
            }
        });
    };
}]).directive('fbParse', ['facebook', function(facebook) {
   return function(scope, elem, attr) {
       FB.XFBML.parse(elem[0]);
   };
}]).directive('gaClickNoTouch', ['$parse', function($parse) {
    return {
        compile: function($element, attr) {
            var fn = $parse(attr['gaClickNoTouch']);
            return function(scope, element, attr) {
                element.on('click', function(event) {
                    scope.$apply(function() {
                        fn(scope, {$event:event});
                    });
                });
            };
        }
    };
}]);