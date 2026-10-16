package=native_expat
$(package)_version=$(expat_version)
$(package)_download_path=$(expat_download_path)
$(package)_file_name=expat-$($(package)_version).tar.gz
$(package)_sha256_hash=$(expat_sha256_hash)
$(package)_build_subdir=build

define $(package)_set_vars
$(package)_config_opts=-DCMAKE_BUILD_TYPE=None -DEXPAT_BUILD_TOOLS=OFF
$(package)_config_opts += -DEXPAT_BUILD_EXAMPLES=OFF -DEXPAT_BUILD_TESTS=OFF -DBUILD_SHARED_LIBS=OFF
endef

define $(package)_config_cmds
  $($(package)_cmake) -S .. -B .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf share lib/cmake
endef
