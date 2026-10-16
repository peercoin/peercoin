package=native_wayland
$(package)_version=1.23.1
$(package)_download_path=https://gitlab.freedesktop.org/wayland/wayland/-/releases/$($(package)_version)/downloads
$(package)_file_name=wayland-$($(package)_version).tar.xz
$(package)_sha256_hash=864fb2a8399e2d0ec39d56e9d9b753c093775beadc6022ce81f441929a81e5ed
$(package)_dependencies=native_expat

define $(package)_set_vars
$(package)_config_opts=--prefix=$(build_prefix) --libdir=lib --buildtype=plain --default-library=static --wrap-mode=nodownload
$(package)_config_opts += -Dlibraries=false -Dscanner=true -Ddtd_validation=false -Ddocumentation=false -Dtests=false
$(package)_config_env=CC="$(build_CC)" CFLAGS="$($(package)_cppflags) $($(package)_cflags)" LDFLAGS="$($(package)_ldflags)"
endef

define $(package)_config_cmds
  meson setup build $($(package)_config_opts)
endef

define $(package)_build_cmds
  meson compile -C build
endef

define $(package)_stage_cmds
  DESTDIR=$($(package)_staging_dir) meson install --no-rebuild -C build
endef

define $(package)_postprocess_cmds
  rm -rf share/aclocal
endef
