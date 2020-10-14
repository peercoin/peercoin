/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef BITCOIN_LIBSECP256K1_CONFIG_H
#define BITCOIN_LIBSECP256K1_CONFIG_H

#undef USE_ASM_X86_64
#undef USE_ECMULT_STATIC_PRECOMPUTATION
#undef USE_EXTERNAL_ASM
#undef USE_EXTERNAL_DEFAULT_CALLBACKS
#undef USE_FIELD_INV_BUILTIN
#undef USE_FIELD_INV_NUM
#undef USE_NUM_GMP
#undef USE_NUM_NONE
#undef USE_SCALAR_INV_BUILTIN
#undef USE_SCALAR_INV_NUM
#undef USE_FORCE_WIDEMUL_INT64
#undef USE_FORCE_WIDEMUL_INT128
#undef ECMULT_WINDOW_SIZE

#define USE_NUM_NONE 1
#define USE_FIELD_INV_BUILTIN 1
#define USE_SCALAR_INV_BUILTIN 1
#define USE_WIDEMUL_64 1
#define ECMULT_WINDOW_SIZE 15

#define ECMULT_GEN_PREC_BITS 4
#define ECMULT_WINDOW_SIZE 15

#endif // BITCOIN_LIBSECP256K1_CONFIG_H
