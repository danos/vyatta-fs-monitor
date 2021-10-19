mount_dep = dependency('mount')
confuse_dep = dependency('libconfuse')
fsmon_deps = [ mount_dep, confuse_dep ]

fsmon_exe = executable('fsmon', 'fsmon_cfg.c', 'fsmon.c', dependencies: fsmon_deps, install : true)

test('basic', find_program('fsmon_test.sh'), args: [ fsmon_exe ])
