angular.module('greenWalletSettingsDirectives', [])
.directive('addressbookItem', ['$compile', function ($compile) {
    var cache = {};
    var getTemplate = function(scope, interactive) {
        var item = scope.item;
        var key = [item.type, item.has_wallet, !!item.href, interactive];
        if (cache[key]) return cache[key];

        var template = '<table><tr><td>';
        if (item.type == 'facebook') {
            template += '<i class="icon-facebook"></i>'
        } else if (item.type == 'email') {
            template += '<i class="glyphicon glyphicon-envelope"></i>'
        }
        template += '</td>';
        var item_name = scope.wallet.hdwallet.priv ? 
                        '<a href="(( send_url(item) ))">(( item.name ))</a>' :
                        '(( item.name ))';  // don't allow opening 'Send' in watch-only
        if (interactive) {
            template += '<td ng-hide="item.renaming">' + item_name;
        } else {
            template += '<td>' + item_name;
        }
        if (item.has_wallet) {
            template += ' <img src="' + BASE_URL + '/static/img/logos/logo-greenaddress.png" height="16"/>';
        }
        template += '</a></td>';
        if (interactive) {  
            template += '<td ng-show="item.renaming">' +
                '<form ng-submit="rename(item.address, item.name)" class="inline">' +
                    '<input type="text" ng-model="item.name" focus-on="addrbook_rename_(( item.address ))" />' +
                    '<input type="submit" class="hide" submitter-scope />' +
                '</form>' +
            '</td>';
        }
                    
        if (window.cordova) {  // no external links in Cordova
            var address = (item.href ? 
                           '<span>(( item.href ))</a>' : 
                           '<span>(( item.address ))</span>')
        } else {
            var address = (item.href ? 
                           '<a ng-href="(( item.href ))" target="_blank">(( item.href ))</a>' : 
                           '<span>(( item.address ))</span>');
        }
        template += '<td>' + address + '</td>';

        template += '<td>';
        if (scope.wallet.hdwallet.priv && item.type != 'facebook') {
            template += 
                        '<a href="" ng-click="start_rename(item)"><i class="glyphicon glyphicon-edit"></i></a> ' + 
                        '<a href="" ng-click="delete(item.address)"><i class="glyphicon glyphicon-trash"></i></a> ';
            if (interactive) {
                template += '<a ng-show="item.renaming" href="" ng-click="submit_me()"><i class="glyphicon glyphicon-floppy-disk"></i></a>';
            }
        }
        template += '</td></tr></table>';

        cache[key] = angular.element(template).find('td');
        return cache[key];
    };

    var linker = function(scope, element, attrs, submittableCtrl) {
        var replaceWith = function(newElements) {
            element.empty();
            for (var i = 0; i < newElements.length; i++) {
                element.append(newElements[i]);;
            }
        }
        replaceWith($compile(getTemplate(scope).clone())(scope));
        
        var replaced = false;
        element.on('mouseover', function() {
            if (replaced) return;
            replaced = true;
            scope.$apply(function() {
                scope.submittableCtrl = submittableCtrl;
                replaceWith($compile(getTemplate(scope, true).clone())(scope));
            });
        });
    };

    return {
        scope: true,
        require: '^submittable',
        restrict: "A",
        link: linker
    };
}]);
