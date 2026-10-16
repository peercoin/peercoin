# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

function(generate_setup_nsi)
  set(abs_top_srcdir ${PROJECT_SOURCE_DIR})
  set(abs_top_builddir ${PROJECT_BINARY_DIR})
  set(PACKAGE_NAME ${CLIENT_NAME})
  set(PACKAGE_URL ${PROJECT_HOMEPAGE_URL})
  set(PACKAGE_TARNAME "peercoin")
  set(PACKAGE_VERSION "${PEERCOIN_VERSION_MAJOR}.${PEERCOIN_VERSION_MINOR}.${PEERCOIN_VERSION_REVISION}.${PEERCOIN_VERSION_BUILD}")
  get_target_property(BITCOIN_GUI_NAME bitcoin-qt OUTPUT_NAME)
  get_target_property(BITCOIN_DAEMON_NAME bitcoind OUTPUT_NAME)
  get_target_property(BITCOIN_CLI_NAME bitcoin-cli OUTPUT_NAME)
  get_target_property(BITCOIN_TX_NAME bitcoin-tx OUTPUT_NAME)
  get_target_property(BITCOIN_WALLET_TOOL_NAME bitcoin-wallet OUTPUT_NAME)
  set(EXEEXT ${CMAKE_EXECUTABLE_SUFFIX})
  configure_file(${PROJECT_SOURCE_DIR}/share/setup.nsi.in ${PROJECT_BINARY_DIR}/bitcoin-win64-setup.nsi USE_SOURCE_PERMISSIONS @ONLY)
endfunction()
