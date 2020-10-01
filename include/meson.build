confdata = configuration_data()
confdata.set('version', meson.project_version())
install_headers(configure_file(input: 'network-config-manager.h.in',
                               output: 'network-config-manager.h',
                               configuration: confdata))
