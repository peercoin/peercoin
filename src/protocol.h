// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __cplusplus
# error This header can only be compiled as C++.
#endif

#ifndef __INCLUDED_PROTOCOL_H__
#define __INCLUDED_PROTOCOL_H__

#include "serialize.h"
#include "netbase.h"
#include <string>
#include "uint256.h"

#define PEERSHARES_PORT  9921
#define RPC_PORT     9922
#define TESTNET_PORT 47891
#define TESTNET_RPC_PORT 47892

#define PEERCOIN_RPC_PORT         9902
#define PEERCOIN_TESTNET_RPC_PORT 9904

extern bool fTestNet;

void GetMessageStart(unsigned char pchMessageStart[], bool fPersistent = false);

static inline unsigned short GetDefaultPort(const bool testnet = fTestNet)
{
    return testnet ? TESTNET_PORT : PEERSHARES_PORT;
}


/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
class CMessageHeader
{
    public:
        CMessageHeader();
        CMessageHeader(const char* pszCommand, unsigned int nMessageSizeIn);

        std::string GetCommand() const;
        bool IsValid() const;

        IMPLEMENT_SERIALIZE
            (
             READWRITE(FLATDATA(pchMessageStart));
             READWRITE(FLATDATA(pchCommand));
             READWRITE(nMessageSize);
             READWRITE(nChecksum);
            )

    // TODO: make private (improves encapsulation)
    public:
        enum { COMMAND_SIZE=12 };
        unsigned char pchMessageStart[4];
        char pchCommand[COMMAND_SIZE];
        unsigned int nMessageSize;
        unsigned int nChecksum;
};

/** nServices flags */
enum
{
    NODE_NETWORK = (1 << 0),
};

/** A CService with information about it as peer */
class CAddress : public CService
{
    public:
        CAddress();
        explicit CAddress(CService ipIn, uint64 nServicesIn=NODE_NETWORK);

        void Init();

        IMPLEMENT_SERIALIZE
            (
             CAddress* pthis = const_cast<CAddress*>(this);
             CService* pip = (CService*)pthis;
             if (fRead)
                 pthis->Init();
             if (nType & SER_DISK)
                 READWRITE(nVersion);
             if ((nType & SER_DISK) ||
                 (nVersion >= CADDR_TIME_VERSION && !(nType & SER_GETHASH)))
                 READWRITE(nTime);
             READWRITE(nServices);
             READWRITE(*pip);
            )

        void print() const;

    // TODO: make private (improves encapsulation)
    public:
        uint64 nServices;

        // disk and network only
        unsigned int nTime;

        // memory only
        int64 nLastTry;
};

/** inv message data */
class CInv
{
    public:
        CInv();
        CInv(int typeIn, const uint256& hashIn);
        CInv(const std::string& strType, const uint256& hashIn);

        IMPLEMENT_SERIALIZE
        (
            READWRITE(type);
            READWRITE(hash);
        )

        friend bool operator<(const CInv& a, const CInv& b);

        bool IsKnownType() const;
        const char* GetCommand() const;
        std::string ToString() const;
        void print() const;

    // TODO: make private (improves encapsulation)
    public:
        int type;
        uint256 hash;
};

#endif // __INCLUDED_PROTOCOL_H__
