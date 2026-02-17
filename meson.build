project(
  'rofi-yubikey-oath',
  'c',
  version : '0.1.0',
  default_options : [
    'warning_level=3', # enables -Wall -Wextra
#    'werror=true',
    'strip=true',
    'c_std=gnu11'
  ]
)
# -------------------------------------------------
# Dependencies (equivalent to PKG_CHECK_MODULES)
# -------------------------------------------------
glib_dep = dependency(
  ['glib-2.0', 'gio-unix-2.0', 'gmodule-2.0'],
  version : '>= 2.40',
  required : true
)
rofi_dep = dependency('rofi', required : true)
pcsclite_dep = dependency('libpcsclite', required : true)

fontconfig_dep = dependency('fontconfig', required : false)
if fontconfig_dep.found()
  add_project_arguments('-DHAVE_FONTCONFIG', language : 'c')
endif
# -------------------------------------------------
# Get Rofi plugin directory from pkg-config
# -------------------------------------------------
rofi_plugins_dir = rofi_dep.get_variable(
  pkgconfig : 'pluginsdir'
)
# -------------------------------------------------
# Compiler flags (equivalent to AM_CFLAGS)
# -------------------------------------------------
add_project_arguments([
  '-Wparentheses',
  '-Winline',
  '-pedantic',
  '-Wunreachable-code'
], language : 'c')
# -------------------------------------------------
# Build plugin module
# -------------------------------------------------
shared_module(
  'yubikey-oath',
  sources : ['src/yubikey-oath.c'],
  dependencies : [glib_dep, rofi_dep, pcsclite_dep, fontconfig_dep],
  install : true,
  install_dir : rofi_plugins_dir,
  name_prefix : '',
)
