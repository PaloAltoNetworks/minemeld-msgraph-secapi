console.log('Loading Microsoft ISG Output WebUI');

(function() {

function MSFTISGSideConfigController($scope, MinemeldConfigService, MineMeldRunningConfigStatusService,
                                       toastr, $modal, ConfirmService, $timeout) {
    var vm = this;

    // side config settings
    vm.client_id = undefined;
    vm.client_secret = undefined;
    vm.tenant_id = undefined;

    vm.loadSideConfig = function() {
        var nodename = $scope.$parent.vm.nodename;

        MinemeldConfigService.getDataFile(nodename + '_side_config')
        .then((result) => {
            if (!result) {
                return;
            }

            if (result.client_id) {
                vm.client_id = result.client_id;
            } else {
                vm.client_id = undefined;
            }

            if (result.client_secret) {
                vm.client_secret = result.client_secret;
            } else {
                vm.client_secret = undefined;
            }

            if (result.tenant_id) {
                vm.tenant_id = result.tenant_id;
            } else {
                vm.tenant_id = undefined;
            }
        }, (error) => {
            toastr.error('ERROR RETRIEVING NODE SIDE CONFIG: ' + error.status);
            vm.client_id = undefined;
            vm.client_secret = undefined;
            vm.tenant_id = undefined;
        });
    };

    vm.saveSideConfig = function() {
        var side_config = {};
        var hup_node = undefined;
        var nodename = $scope.$parent.vm.nodename;

        if (vm.client_id) {
            side_config.client_id = vm.client_id;
        }
        if (vm.client_secret) {
            side_config.client_secret = vm.client_secret;
        }
        if (vm.tenant_id) {
            side_config.tenant_id = vm.tenant_id;
        }

        return MinemeldConfigService.saveDataFile(
            nodename + '_side_config',
            side_config,
            nodename
        );
    };

    vm.setClientID = function() {
        var mi = $modal.open({
            templateUrl: '/extensions/webui/microsoftISGWebui/isg.output.scid.modal.html',
            controller: ['$modalInstance', MSFTISGClientIDController],
            controllerAs: 'vm',
            bindToController: true,
            backdrop: 'static',
            animation: false
        });

        mi.result.then((result) => {
            vm.client_id = result.client_id;

            return vm.saveSideConfig().then((result) => {
                toastr.success('CLIENT ID SET');
                vm.loadSideConfig();
            }, (error) => {
                toastr.error('ERROR SETTING CLIENT ID: ' + error.statusText);
            });
        });
    };
    vm.setClientSecret = function() {
        var mi = $modal.open({
            templateUrl: '/extensions/webui/microsoftISGWebui/isg.output.scs.modal.html',
            controller: ['$modalInstance', MSFTISGClientSecretController],
            controllerAs: 'vm',
            bindToController: true,
            backdrop: 'static',
            animation: false
        });

        mi.result.then((result) => {
            vm.client_secret = result.client_secret;

            return vm.saveSideConfig().then((result) => {
                toastr.success('CLIENT SECRET SET');
                vm.loadSideConfig();
            }, (error) => {
                toastr.error('ERROR SETTING CLIENT SECRET: ' + error.statusText);
            });
        });
    };
    vm.setTenantID = function() {
        var mi = $modal.open({
            templateUrl: '/extensions/webui/microsoftISGWebui/isg.output.stid.modal.html',
            controller: ['$modalInstance', MSFTISGTenantIDController],
            controllerAs: 'vm',
            bindToController: true,
            backdrop: 'static',
            animation: false
        });

        mi.result.then((result) => {
            vm.tenant_id = result.tenant_id;

            return vm.saveSideConfig().then((result) => {
                toastr.success('TENANT ID SET');
                vm.loadSideConfig();
            }, (error) => {
                toastr.error('ERROR SETTING TENANT ID: ' + error.statusText);
            });
        });
    };

    vm.loadSideConfig();
}

function MSFTISGClientSecretController($modalInstance) {
    var vm = this;

    vm.client_secret = undefined;
    vm.client_secret2 = undefined;

    vm.valid = function() {
        if (vm.client_secret2 !== vm.client_secret) {
            angular.element('#fgPassword1').addClass('has-error');
            angular.element('#fgPassword2').addClass('has-error');

            return false;
        }
        angular.element('#fgPassword1').removeClass('has-error');
        angular.element('#fgPassword2').removeClass('has-error');

        if (!vm.client_secret) {
            return false;
        }

        return true;
    };

    vm.save = function() {
        var result = {};

        result.client_secret = vm.client_secret;

        $modalInstance.close(result);
    }

    vm.cancel = function() {
        $modalInstance.dismiss();
    }
}

function MSFTISGClientIDController($modalInstance) {
    var vm = this;

    vm.client_id = undefined;

    vm.valid = function() {
        if (!vm.client_id) {
            return false;
        }

        return true;
    };

    vm.save = function() {
        var result = {};

        result.client_id = vm.client_id;

        $modalInstance.close(result);
    }

    vm.cancel = function() {
        $modalInstance.dismiss();
    }
}

function MSFTISGTenantIDController($modalInstance) {
    var vm = this;

    vm.tenant_id = undefined;

    vm.valid = function() {
        if (!vm.tenant_id) {
            return false;
        }

        return true;
    };

    vm.save = function() {
        var result = {};

        result.tenant_id = vm.tenant_id;

        $modalInstance.close(result);
    }

    vm.cancel = function() {
        $modalInstance.dismiss();
    }
}

angular.module('microsoftISGWebui', [])
    .controller('MSFTISGSideConfigController', [
        '$scope', 'MinemeldConfigService', 'MineMeldRunningConfigStatusService',
        'toastr', '$modal', 'ConfirmService', '$timeout',
        MSFTISGSideConfigController
    ])
    .config(['$stateProvider', function($stateProvider) {
        $stateProvider.state('nodedetail.msftisgoutputinfo', {
            templateUrl: '/extensions/webui/microsoftISGWebui/isg.output.info.html',
            controller: 'NodeDetailInfoController',
            controllerAs: 'vm'
        });
    }])
    .run(['NodeDetailResolver', '$state', function(NodeDetailResolver, $state) {
        NodeDetailResolver.registerClass('microsoft_isg.node.Output', {
            tabs: [{
                icon: 'fa fa-circle-o',
                tooltip: 'INFO',
                state: 'nodedetail.msftisgoutputinfo',
                active: false
            },
            {
                icon: 'fa fa-area-chart',
                tooltip: 'STATS',
                state: 'nodedetail.stats',
                active: false
            },
            {
                icon: 'fa fa-asterisk',
                tooltip: 'GRAPH',
                state: 'nodedetail.graph',
                active: false
            }]
        });

        // if a nodedetail is already shown, reload the current state to apply changes
        // we should definitely find a better way to handle this...
        if ($state.$current.toString().startsWith('nodedetail.')) {
            $state.reload();
        }
    }]);
})();