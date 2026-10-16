package=libxkbcommon
$(package)_version=1.13.2
$(package)_download_path=https://github.com/xkbcommon/libxkbcommon/archive/refs/tags
$(package)_download_file=xkbcommon-$($(package)_version).tar.gz
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=acc4d5f7c3cbba5f9f8d08d8bdbeede84ecede46792f47929aa9321873385528
$(package)_dependencies=libxcb

define $(package)_set_vars
$(package)_config_opts = --prefix=$($($(package)_type)_prefix) --libdir=lib
$(package)_config_opts += --buildtype=plain --default-library=static --wrap-mode=nodownload
$(package)_config_opts += -Denable-tools=false -Denable-docs=false
$(package)_config_opts += -Denable-wayland=false -Denable-xkbregistry=false
$(package)_config_opts += -Denable-bash-completion=false
$(package)_config_opts += -Dxkb-config-root=/usr/share/X11/xkb
$(package)_config_opts += -Dxkb-config-extra-path=/etc/xkb
$(package)_config_opts += -Dx-locale-root=/usr/share/X11/locale
$(package)_config_opts += $($(package)_cross_file)
$(package)_config_env = CC="$($(package)_cc)"
$(package)_config_env += CFLAGS="$($(package)_cppflags) $($(package)_cflags)"
$(package)_config_env += LDFLAGS="$($(package)_ldflags)"
$(package)_config_env += AR="$($(package)_ar)"
$(package)_config_env += NM="$($(package)_nm)"
$(package)_config_env += RANLIB="$($(package)_ranlib)"
$(package)_config_env += STRIP="$($($(package)_type)_STRIP)"
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

# LDFLAGS are supplied through Meson; putting them in the compiler wrapper breaks Clang compile-only probes.
define $(package)_preprocess_cmds
  printf '%s\n' '#!/bin/sh' 'exec $($(package)_cc) $($(package)_cppflags) $($(package)_cflags) "$$$$@"' > depends-cc && \
  chmod +x depends-cc && \
  printf '%s\n' \
    '[binaries]' \
    "c = '$($(package)_build_dir)/depends-cc'" \
    "ar = '$($(package)_ar)'" \
    "strip = '$($($(package)_type)_STRIP)'" \
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

define $(package)_config_cmds
  meson setup build $($(package)_config_opts)
endef

define $(package)_build_cmds
  meson compile -C build xkbcommon xkbcommon-x11
endef

define $(package)_stage_cmds
  DESTDIR=$($(package)_staging_dir) meson install --no-rebuild -C build
endef
