network_config_manager_generator = configure_file(
                                         input : 'network-config-manager-generator.service.in',
                                         output : 'network-config-manager-generator.service',
                                         configuration : substs)
                                         install_data(network_config_manager_generator,
                                         install_dir : '/lib/systemd/system')

nnetwork_config_manager_yaml_generator = configure_file(
                                   input : 'network-config-manager-yaml-generator.service.in',
                                   output : 'network-config-manager-yaml-generator.service',
                                   configuration : substs)
                                   install_data(nnetwork_config_manager_yaml_generator,
                                   install_dir : '/lib/systemd/system')
