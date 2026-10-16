package=wayland
$(package)_version=$(native_$(package)_version)
$(package)_download_path=$(native_$(package)_download_path)
$(package)_file_name=$(native_$(package)_file_name)
$(package)_sha256_hash=$(native_$(package)_sha256_hash)
$(package)_dependencies=libffi native_wayland

define $(package)_set_vars
$(package)_config_opts=--prefix=$(host_prefix) --libdir=lib --buildtype=plain --default-library=static --wrap-mode=nodownload
$(package)_config_opts += -Dlibraries=true -Dscanner=false -Ddocumentation=false -Dtests=false
$(package)_config_opts += $($(package)_cross_file)
$(package)_config_env=CC="$($(package)_cc)" CFLAGS="$($(package)_cppflags) $($(package)_cflags)" LDFLAGS="$($(package)_ldflags)"
$(package)_config_env += AR="$($(package)_ar)" NM="$($(package)_nm)" RANLIB="$($(package)_ranlib)"
$(package)_config_env += PKG_CONFIG_PATH_FOR_BUILD=$(build_prefix)/lib/pkgconfig:$(build_prefix)/share/pkgconfig
endef

ifneq ($(host),$(build))
$(package)_cpu_family_i686=x86
$(package)_cpu_family_x86_64=x86_64
$(package)_cpu_family_arm=arm
$(package)_cpu_family_aarch64=aarch64
$(package)_cpu_family_riscv32=riscv32
$(package)_cpu_family_riscv64=riscv64
$(package)_cpu_family_powerpc=ppc
$(package)_cpu_family_powerpc64=ppc64
$(package)_cpu_family_powerpc64le=ppc64
$(package)_endian_i686=little
$(package)_endian_x86_64=little
$(package)_endian_arm=little
$(package)_endian_aarch64=little
$(package)_endian_riscv32=little
$(package)_endian_riscv64=little
$(package)_endian_powerpc=big
$(package)_endian_powerpc64=big
$(package)_endian_powerpc64le=little
$(package)_cross_file=--cross-file=depends-cross-file.ini

define $(package)_preprocess_cmds
  printf '%s\n' '#!/bin/sh' 'exec $($(package)_cc) $($(package)_cppflags) $($(package)_cflags) "$$$$@"' > depends-cc && \
  chmod +x depends-cc && \
  printf '%s\n' \
    '[binaries]' \
    "c = '$($(package)_build_dir)/depends-cc'" \
    "ar = '$($(package)_ar)'" \
    "strip = '$(host_STRIP)'" \
    "pkg-config = 'pkg-config'" \
    '[properties]' \
    'needs_exe_wrapper = true' \
    '[host_machine]' \
    "system = '$(host_os)'" \
    "cpu_family = '$($(package)_cpu_family_$(host_arch))'" \
    "cpu = '$(host_arch)'" \
    "endian = '$($(package)_endian_$(host_arch))'" \
    > depends-cross-file.ini
endef
endif

ifeq ($(host),$(build))
define $(package)_config_cmds
  PKG_CONFIG_PATH=$(build_prefix)/lib/pkgconfig:$(build_prefix)/share/pkgconfig \
  meson setup build $($(package)_config_opts)
endef
else
define $(package)_config_cmds
  meson setup build $($(package)_config_opts)
endef
endif

define $(package)_build_cmds
  meson compile -C build
endef

define $(package)_stage_cmds
  DESTDIR=$($(package)_staging_dir) meson install --no-rebuild -C build
endef
