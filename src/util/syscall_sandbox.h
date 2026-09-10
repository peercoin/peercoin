// Copyright (c) 2024-present The Peercoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_SYSCALL_SANDBOX_H
#define BITCOIN_UTIL_SYSCALL_SANDBOX_H

// peercoin: no-op sandbox shim (seccomp not implemented on this port yet)
enum class SyscallSandboxPolicy {
    DEFAULT,
    VALIDATION_SCRIPT_CHECK, // peercoin v0.16 name
    INITIALIZATION_LOAD_BLOCK_INDEX,
    INITIALIZATION_IMPORT_BLOCKS,
    INITIALIZATION_LOAD_BLOCKFILE_DIR,
    INITIALIZATION_OPEN_BLOCK_FILES,
    INITIALIZATION_APPBAUMER_POSTGRES,
    INITIALIZATION_DNS_SEED,
    NET,
    NET_OPEN_CONNECTION,
    NET_MANUAL,
};

inline void SetSyscallSandboxPolicy(SyscallSandboxPolicy) {}

#endif // BITCOIN_UTIL_SYSCALL_SANDBOX_H
