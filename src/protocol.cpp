// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2012-2013 The Peercoin developers
// Copyright (c) 2013-2014 The Peershares developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "protocol.h"
#include "util.h"
#include "netbase.h"

#ifndef WIN32
# include <arpa/inet.h>
#endif

// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ascii, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.

// Public testnet message start
// unsigned char pchMessageStartTestBitcoin[4] = { 0xfa, 0xbf, 0xb5, 0xda };
static unsigned char pchMessageStartTestOld[4] = { 0xdb, 0xe1, 0xf2, 0xf6 };
static unsigned char pchMessageStartTestNew[4] = { 0xcb, 0xf2, 0xc0, 0xef };
static unsigned int nMessageStartTestSwitchTime = 1346200000;

// Peershares message start (switched from Bitcoin's in Peercoin v0.2)
static unsigned char pchMessageStartBitcoin[4] = { 0xf9, 0xbe, 0xb4, 0xd9 };
static unsigned char pchMessageStartPeershares[4] = { 0xe6, 0xe8, 0xe9, 0xe5 };
static unsigned int nMessageStartSwitchTime = 1347300000;

void GetMessageStart(unsigned char pchMessageStart[], bool fPersistent)
{
    if (fTestNet)
        memcpy(pchMessageStart, (fPersistent || GetAdjustedTime() > nMessageStartTestSwitchTime)? pchMessageStartTestNew : pchMessageStartTestOld, sizeof(pchMessageStartTestNew));
    else
        memcpy(pchMessageStart, (fPersistent || GetAdjustedTime() > nMessageStartSwitchTime)? pchMessageStartPeershares : pchMessageStartBitcoin, sizeof(pchMessageStartPeershares));
}

static const char* ppszTypeName[] =
{
    "ERROR",
    "tx",
    "block",
};

CMessageHeader::CMessageHeader()
{
    GetMessageStart(pchMessageStart);
    memset(pchCommand, 0, sizeof(pchCommand));
    pchCommand[1] = 1;
    nMessageSize = -1;
    nChecksum = 0;
}

CMessageHeader::CMessageHeader(const char* pszCommand, unsigned int nMessageSizeIn)
{
    GetMessageStart(pchMessageStart);
    strncpy(pchCommand, pszCommand, COMMAND_SIZE);
    nMessageSize = nMessageSizeIn;
    nChecksum = 0;
}

std::string CMessageHeader::GetCommand() const
{
    if (pchCommand[COMMAND_SIZE-1] == 0)
        return std::string(pchCommand, pchCommand + strlen(pchCommand));
    else
        return std::string(pchCommand, pchCommand + COMMAND_SIZE);
}

bool CMessageHeader::IsValid() const
{
    // Check start string
    unsigned char pchMessageStartProtocol[4];
    GetMessageStart(pchMessageStartProtocol);
    if (memcmp(pchMessageStart, pchMessageStartProtocol, sizeof(pchMessageStart)) != 0)
        return false;

    // Check the command string for errors
    for (const char* p1 = pchCommand; p1 < pchCommand + COMMAND_SIZE; p1++)
    {
        if (*p1 == 0)
        {
            // Must be all zeros after the first zero
            for (; p1 < pchCommand + COMMAND_SIZE; p1++)
                if (*p1 != 0)
                    return false;
        }
        else if (*p1 < ' ' || *p1 > 0x7E)
            return false;
    }

    // Message size
    if (nMessageSize > MAX_SIZE)
    {
        printf("CMessageHeader::IsValid() : (%s, %u bytes) nMessageSize > MAX_SIZE\n", GetCommand().c_str(), nMessageSize);
        return false;
    }

    return true;
}



CAddress::CAddress() : CService()
{
    Init();
}

CAddress::CAddress(CService ipIn, uint64 nServicesIn) : CService(ipIn)
{
    Init();
    nServices = nServicesIn;
}

void CAddress::Init()
{
    nServices = NODE_NETWORK;
    nTime = 100000000;
    nLastTry = 0;
}

CInv::CInv()
{
    type = 0;
    hash = 0;
}

CInv::CInv(int typeIn, const uint256& hashIn)
{
    type = typeIn;
    hash = hashIn;
}

CInv::CInv(const std::string& strType, const uint256& hashIn)
{
    unsigned int i;
    for (i = 1; i < ARRAYLEN(ppszTypeName); i++)
    {
        if (strType == ppszTypeName[i])
        {
            type = i;
            break;
        }
    }
    if (i == ARRAYLEN(ppszTypeName))
        throw std::out_of_range(strprintf("CInv::CInv(string, uint256) : unknown type '%s'", strType.c_str()));
    hash = hashIn;
}

bool operator<(const CInv& a, const CInv& b)
{
    return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
}

bool CInv::IsKnownType() const
{
    return (type >= 1 && type < (int)ARRAYLEN(ppszTypeName));
}

const char* CInv::GetCommand() const
{
    if (!IsKnownType())
        throw std::out_of_range(strprintf("CInv::GetCommand() : type=%d unknown type", type));
    return ppszTypeName[type];
}

std::string CInv::ToString() const
{
    return strprintf("%s %s", GetCommand(), hash.ToString().substr(0,20).c_str());
}

void CInv::print() const
{
    printf("CInv(%s)\n", ToString().c_str());
}

