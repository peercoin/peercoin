package=libffi
$(package)_version=3.4.6
$(package)_download_path=https://github.com/libffi/libffi/releases/download/v$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=b0dea9df23c863a7a50e825440f3ebffabd65df1497108e5d437747843895a4e

define $(package)_set_vars
$(package)_config_opts=--disable-shared --disable-docs --disable-multi-os-directory
# The AArch64 backend uses GNU inline assembly and needs GNU C extensions.
$(package)_cflags += -std=gnu11
endef

define $(package)_preprocess_cmds
  cp $(BASEDIR)/config.guess $(BASEDIR)/config.sub .
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf share lib/*.la
endef
