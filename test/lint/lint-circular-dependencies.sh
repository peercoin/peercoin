#!/usr/bin/env bash
#
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check for circular dependencies

export LC_ALL=C

EXPECTED_CIRCULAR_DEPENDENCIES=(
    "chain -> pow -> chain"
    "chainparamsbase -> util -> chainparamsbase"
    "checkpointsync -> validation -> checkpointsync"
    "consensus/tx_verify -> validation -> consensus/tx_verify"
    "init -> net_processing -> init"
    "init -> rpc/server -> init"
    "init -> txdb -> init"
    "init -> validation -> init"
    "init -> validationinterface -> init"
    "kernel -> validation -> kernel"
    "qt/guiutil -> qt/walletmodel -> qt/guiutil"
    "qt/mintingtablemodel -> qt/walletmodel -> qt/mintingtablemodel"
    "random -> util -> random"
    "sync -> util -> sync"
    "wallet/init -> wallet/wallet -> wallet/init"
    "wallet/rpcwallet -> wallet/wallet -> wallet/rpcwallet"
    "checkpointsync -> validation -> warnings -> checkpointsync"
    "init -> wallet/init -> wallet/rpcwallet -> init"
    "qt/bitcoingui -> qt/walletframe -> qt/walletview -> qt/bitcoingui"
    "init -> wallet/init -> wallet/rpcwallet -> rpc/mining -> init"
    "checkpoints -> validation -> checkpoints"
    "policy/policy -> validation -> policy/policy"
    "qt/addresstablemodel -> qt/walletmodel -> qt/addresstablemodel"
    "qt/bantablemodel -> qt/clientmodel -> qt/bantablemodel"
    "qt/bitcoingui -> qt/utilitydialog -> qt/bitcoingui"
    "qt/bitcoingui -> qt/walletframe -> qt/bitcoingui"
    "qt/clientmodel -> qt/peertablemodel -> qt/clientmodel"
    "qt/paymentserver -> qt/walletmodel -> qt/paymentserver"
    "qt/recentrequeststablemodel -> qt/walletmodel -> qt/recentrequeststablemodel"
    "qt/sendcoinsdialog -> qt/walletmodel -> qt/sendcoinsdialog"
    "qt/transactiontablemodel -> qt/walletmodel -> qt/transactiontablemodel"
    "qt/walletmodel -> qt/walletmodeltransaction -> qt/walletmodel"
    "txmempool -> validation -> txmempool"
    "validation -> validationinterface -> validation"
    "wallet/coincontrol -> wallet/wallet -> wallet/coincontrol"
    "wallet/wallet -> wallet/walletdb -> wallet/wallet"
    "qt/guiutil -> qt/walletmodel -> qt/optionsmodel -> qt/guiutil"
    "txmempool -> validation -> validationinterface -> txmempool"
    "qt/guiutil -> qt/walletmodel -> qt/optionsmodel -> qt/intro -> qt/guiutil"
    "qt/addressbookpage -> qt/bitcoingui -> qt/walletframe -> qt/walletview -> qt/addressbookpage"
    "qt/addressbookpage -> qt/bitcoingui -> qt/walletframe -> qt/walletview -> qt/receivecoinsdialog -> qt/addressbookpage"
    "qt/addressbookpage -> qt/bitcoingui -> qt/walletframe -> qt/walletview -> qt/signverifymessagedialog -> qt/addressbookpage"
    "qt/addressbookpage -> qt/bitcoingui -> qt/walletframe -> qt/walletview -> qt/multisigdialog -> qt/multisigaddressentry -> qt/addressbookpage"
    "qt/addressbookpage -> qt/bitcoingui -> qt/walletframe -> qt/walletview -> qt/multisigdialog -> qt/sendcoinsentry -> qt/addressbookpage"
)

EXIT_CODE=0

CIRCULAR_DEPENDENCIES=()

IFS=$'\n'
for CIRC in $(cd src && ../contrib/devtools/circular-dependencies.py {*,*/*,*/*/*}.{h,cpp} | sed -e 's/^Circular dependency: //'); do
    CIRCULAR_DEPENDENCIES+=($CIRC)
    IS_EXPECTED_CIRC=0
    for EXPECTED_CIRC in "${EXPECTED_CIRCULAR_DEPENDENCIES[@]}"; do
        if [[ "${CIRC}" == "${EXPECTED_CIRC}" ]]; then
            IS_EXPECTED_CIRC=1
            break
        fi
    done
    if [[ ${IS_EXPECTED_CIRC} == 0 ]]; then
        echo "A new circular dependency in the form of \"${CIRC}\" appears to have been introduced."
        echo
        EXIT_CODE=1
    fi
done

for EXPECTED_CIRC in "${EXPECTED_CIRCULAR_DEPENDENCIES[@]}"; do
    IS_PRESENT_EXPECTED_CIRC=0
    for CIRC in "${CIRCULAR_DEPENDENCIES[@]}"; do
        if [[ "${CIRC}" == "${EXPECTED_CIRC}" ]]; then
            IS_PRESENT_EXPECTED_CIRC=1
            break
        fi
    done
    if [[ ${IS_PRESENT_EXPECTED_CIRC} == 0 ]]; then
        echo "Good job! The circular dependency \"${EXPECTED_CIRC}\" is no longer present."
        echo "Please remove it from EXPECTED_CIRCULAR_DEPENDENCIES in $0"
        echo "to make sure this circular dependency is not accidentally reintroduced."
        echo
        EXIT_CODE=1
    fi
done

exit ${EXIT_CODE}
