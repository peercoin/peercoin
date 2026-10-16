package=qrencode
$(package)_version=4.1.1
$(package)_download_path=https://fukuchi.org/works/qrencode
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=da448ed4f52aba6bcb0cd48cac0dd51b8692bccc4cd127431402fca6f8171e8e
$(package)_github_download_path=https://github.com/fukuchi/libqrencode/archive/refs/tags
$(package)_github_download_file=v$($(package)_version).tar.gz
$(package)_github_sha256_hash=5385bc1b8c2f20f3b91d258bf8ccc8cf62023935df2d2676b5b67049f31a049c
$(package)_patches=cmake_fixups.patch

# The GitHub tag archive omits generated Autotools files from the release tarball.
# Both archives contain the same sources used by our CMake build.
define $(package)_fetch_cmds
  $(call fetch_file_inner,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash)) || \
  $(call fetch_file_inner,$(package),$($(package)_github_download_path),$($(package)_github_download_file),$($(package)_file_name),$($(package)_github_sha256_hash))
endef

define $(package)_extract_cmds
  mkdir -p $($(package)_extract_dir) && \
  echo "$($(package)_sha256_hash)  $($(package)_source)" > $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  if ! $(build_SHA256SUM) -c $($(package)_extract_dir)/.$($(package)_file_name).hash >/dev/null 2>&1; then \
    echo "$($(package)_github_sha256_hash)  $($(package)_source)" > $($(package)_extract_dir)/.$($(package)_file_name).hash && \
    $(build_SHA256SUM) -c $($(package)_extract_dir)/.$($(package)_file_name).hash; \
  fi && \
  $(build_TAR) --no-same-owner --strip-components=1 -xf $($(package)_source)
endef

define $(package)_set_vars
$(package)_config_opts := -DWITH_TOOLS=NO -DWITH_TESTS=NO -DGPROF=OFF -DCOVERAGE=OFF
$(package)_config_opts += -DCMAKE_DISABLE_FIND_PACKAGE_PNG=TRUE -DWITHOUT_PNG=ON
$(package)_config_opts += -DCMAKE_DISABLE_FIND_PACKAGE_ICONV=TRUE
$(package)_cflags += -Wno-int-conversion -Wno-implicit-function-declaration
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/cmake_fixups.patch
endef


define $(package)_config_cmds
  $($(package)_cmake) -S . -B .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf share
endef
