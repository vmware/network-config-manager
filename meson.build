project('network-config-manager', 'c',
        version : '1.0',
        license : 'Apache-2.0',
        default_options: [
                'c_std=gnu99',
                'localstatedir=/var',
        ],
        meson_version : '>= 0.40')

so_version = '1'

conf = configuration_data()
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set_quoted('PACKAGE_STRING',  meson.project_name() + ' ' + meson.project_version())

substs = configuration_data()
substs.set('PACKAGE_URL',          'https://github.com/vmware/network-config-manager')
substs.set('PACKAGE_VERSION',      meson.project_version())
conf.set_quoted('PKGSYSCONFDIR',   get_option('sysconfdir'))

#####################################################################

cc = meson.get_compiler('c')

c_args = '''
        -Wextra
        -Werror=undef
        -Werror=format=2
        -Wformat-security
        -Wformat-nonliteral
        -Wlogical-op
        -Wmissing-include-dirs
        -Werror=old-style-definition
        -Werror=pointer-arith
        -Winit-self
        -Wdeclaration-after-statement
        -Wfloat-equal
        -Wsuggest-attribute=noreturn
        -Werror=missing-prototypes
        -Werror=implicit-function-declaration
        -Werror=missing-declarations
        -Werror=return-type
        -Werror=incompatible-pointer-types
        -Werror=shadow
        -Wstrict-prototypes
        -Wredundant-decls
        -Wmissing-noreturn
        -Wendif-labels
        -Wstrict-aliasing=2
        -Wwrite-strings
        -Wno-unused-parameter
        -Wno-missing-field-initializers
        -Wno-unused-result
        -Werror=overflow
        -Werror=sign-compare
        -Wdate-time
        -Wnested-externs
        -ffast-math
        -fno-common
        -fdiagnostics-show-option
        -fno-strict-aliasing
        -fvisibility=hidden
        -fstack-protector
        -fstack-protector-strong
        -fPIE
        --param=ssp-buffer-size=4
'''.split()

foreach arg : c_args
        if cc.has_argument(arg)
                add_project_arguments(arg, language : 'c')
        endif
endforeach

conf.set('_GNU_SOURCE', true)
conf.set('__SANE_USERSPACE_TYPES__', true)

conf.set('SIZEOF_PID_T', cc.sizeof('pid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_UID_T', cc.sizeof('uid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_GID_T', cc.sizeof('gid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_DEV_T', cc.sizeof('dev_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_INO_T', cc.sizeof('ino_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_TIME_T', cc.sizeof('time_t', prefix : '#include <sys/time.h>'))
conf.set('SIZEOF_RLIM_T', cc.sizeof('rlim_t', prefix : '#include <sys/resource.h>'))

foreach ident : [
        ['gettid',            '''#include <sys/types.h>'''],
]
        have = cc.has_function(ident[0], prefix : ident[1])
        conf.set10('HAVE_' + ident[0].to_upper(), have)
endforeach

if cc.has_function('getrandom', prefix : '''#include <sys/random.h>''')
        conf.set10('USE_SYS_RANDOM_H', true)
        conf.set10('HAVE_GETRANDOM', true)
else
        have = cc.has_function('getrandom', prefix : '''#include <linux/random.h>''')
        conf.set10('USE_SYS_RANDOM_H', false)
        conf.set10('HAVE_GETRANDOM', have)
endif

############################################################

config_h = configure_file(
        output : 'config.h',
        configuration : conf)
add_project_arguments('-include', 'config.h', language : 'c')

subdir('include')
subdir('src')
#subdir('doc')
subdir('units')

############################################################

libsystemd = dependency('libsystemd',
                     version : '>= 230')

glib_dep = dependency('glib-2.0')
udev_dep = dependency('libudev')
yaml_dep = dependency('yaml-0.1')

includes = include_directories('src/cli',
                               'src/dbus',
                               'src/dns',
                               'src/dracut',
                               'src/lib-network/netlink',
                               'src/lib-network/networkd',
                               'src/manager',
                               'src/share',
                               'src/udev',
                               'src/yaml',
                               'include',
                               '.')

network_config_managerlib = library('network_config_manager',
                        network_config_manager_sources,
                        include_directories: includes,
                        dependencies : [
                        libsystemd, glib_dep, udev_dep, yaml_dep],
                        install: true,
                        version: meson.project_version(),
                        soversion: so_version)

network_config_manager = executable(
                              'nmctl',
                              network_config_manager_sources,
                              include_directories : includes,
                              dependencies : [
                              libsystemd, glib_dep, udev_dep, yaml_dep],
                              install : true)

pkg = import('pkgconfig')
pkg.generate(libraries : network_config_managerlib,
              version : meson.project_version(),
              name : 'libnetwork_config_manager',
              filebase : 'network-config-manager',
              description : 'A library for setting the network configuration manager files.')
