// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2012 The Peercoin developers
// Copyright (c) 2013-2014 The Peershares developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UTIL_H
#define BITCOIN_UTIL_H

#include "uint256.h"

#ifndef WIN32
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#else
#ifndef _WIN64
typedef int pid_t; /* define for windows compatiblity */
#endif
#endif
#include <map>
#include <vector>
#include <string>

#include <boost/thread.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/interprocess/sync/interprocess_recursive_mutex.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>
#include <boost/interprocess/sync/interprocess_semaphore.hpp>
#include <boost/interprocess/sync/lock_options.hpp>
#include <boost/date_time/gregorian/gregorian_types.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>

#include <openssl/sha.h>
#include <openssl/ripemd.h>

#include "netbase.h" // for AddTimeData

typedef long long  int64;
typedef unsigned long long  uint64;

static const int64 COIN = 1000000;
static const int64 CENT = 10000;

#define loop                for (;;)
#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))
#define UBEGIN(a)           ((unsigned char*)&(a))
#define UEND(a)             ((unsigned char*)&((&(a))[1]))
#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0]))
#define printf              OutputDebugStringF

#ifdef snprintf
#undef snprintf
#endif
#define snprintf my_snprintf

#ifndef PRI64d
#if defined(_MSC_VER) || defined(__MSVCRT__)
#define PRI64d  "I64d"
#define PRI64u  "I64u"
#define PRI64x  "I64x"
#else
#define PRI64d  "lld"
#define PRI64u  "llu"
#define PRI64x  "llx"
#endif
#endif

// This is needed because the foreach macro can't get over the comma in pair<t1, t2>
#define PAIRTYPE(t1, t2)    std::pair<t1, t2>

// Align by increasing pointer, must have extra space at end of buffer
template <size_t nBytes, typename T>
T* alignup(T* p)
{
    union
    {
        T* ptr;
        size_t n;
    } u;
    u.ptr = p;
    u.n = (u.n + (nBytes-1)) & ~(nBytes-1);
    return u.ptr;
}

#ifdef WIN32
#define MSG_NOSIGNAL        0
#define MSG_DONTWAIT        0

#ifndef S_IRUSR
#define S_IRUSR             0400
#define S_IWUSR             0200
#endif
#define unlink              _unlink
#else
#define _vsnprintf(a,b,c,d) vsnprintf(a,b,c,d)
#define strlwr(psz)         to_lower(psz)
#define _strlwr(psz)        to_lower(psz)
#define MAX_PATH            1024
inline void Sleep(int64 n)
{
    /*Boost has a year 2038 problem— if the request sleep time is past epoch+2^31 seconds the sleep returns instantly.
      So we clamp our sleeps here to 10 years and hope that boost is fixed by 2028.*/
    boost::thread::sleep(boost::get_system_time() + boost::posix_time::milliseconds(n>315576000000LL?315576000000LL:n));
}
#endif

#ifndef THROW_WITH_STACKTRACE
#define THROW_WITH_STACKTRACE(exception)  \
{                                         \
    LogStackTrace();                      \
    throw (exception);                    \
}
void LogStackTrace();
#endif






extern std::map<std::string, std::string> mapArgs;
extern std::map<std::string, std::vector<std::string> > mapMultiArgs;
extern std::map<std::string, std::string> mapPeercoinArgs;
extern bool fDebug;
extern bool fPrintToConsole;
extern bool fPrintToDebugger;
extern bool fRequestShutdown;
extern bool fShutdown;
extern bool fDaemon;
extern bool fServer;
extern bool fCommandLine;
extern std::string strMiscWarning;
extern bool fTestNet;
extern bool fNoListen;
extern bool fLogTimestamps;

void RandAddSeed();
void RandAddSeedPerfmon();
int OutputDebugStringF(const char* pszFormat, ...);
int my_snprintf(char* buffer, size_t limit, const char* format, ...);

/* It is not allowed to use va_start with a pass-by-reference argument.
   (C++ standard, 18.7, paragraph 3). Use a dummy argument to work around this, and use a
   macro to keep similar semantics.
*/
std::string real_strprintf(const std::string &format, int dummy, ...);
#define strprintf(format, ...) real_strprintf(format, 0, __VA_ARGS__)

bool error(const char *format, ...);
void LogException(std::exception* pex, const char* pszThread);
void PrintException(std::exception* pex, const char* pszThread);
void PrintExceptionContinue(std::exception* pex, const char* pszThread);
void ParseString(const std::string& str, char c, std::vector<std::string>& v);
std::string FormatMoney(int64 n, bool fPlus=false);
bool ParseMoney(const std::string& str, int64& nRet);
bool ParseMoney(const char* pszIn, int64& nRet);
std::vector<unsigned char> ParseHex(const char* psz);
std::vector<unsigned char> ParseHex(const std::string& str);
bool IsHex(const std::string& str);
std::vector<unsigned char> DecodeBase64(const char* p, bool* pfInvalid = NULL);
std::string DecodeBase64(const std::string& str);
std::string EncodeBase64(const unsigned char* pch, size_t len);
std::string EncodeBase64(const std::string& str);
void ParseParameters(int argc, const char*const argv[]);
bool WildcardMatch(const char* psz, const char* mask);
bool WildcardMatch(const std::string& str, const std::string& mask);
int GetFilesize(FILE* file);
boost::filesystem::path GetDefaultDataDir();
boost::filesystem::path GetDefaultPeercoinDataDir();
const boost::filesystem::path &GetDataDir(bool fNetSpecific = true);
const boost::filesystem::path &GetPeercoinDataDir(bool fNetSpecific = true);
boost::filesystem::path GetConfigFile();
boost::filesystem::path GetPeercoinConfigFile();
boost::filesystem::path GetPidFile();
void CreatePidFile(const boost::filesystem::path &path, pid_t pid);
void ReadConfigFile(std::map<std::string, std::string>& mapSettingsRet, std::map<std::string, std::vector<std::string> >& mapMultiSettingsRet);
void ReadPeercoinConfigFile(std::map<std::string, std::string>& mapSettingsRet);
bool GetStartOnSystemStartup();
bool SetStartOnSystemStartup(bool fAutoStart);
void ShrinkDebugFile();
int GetRandInt(int nMax);
uint64 GetRand(uint64 nMax);
uint256 GetRandHash();
int64 GetTime();
void SetMockTime(int64 nMockTimeIn);
int64 GetAdjustedTime();
std::string FormatFullVersion();
std::string FormatSubVersion(const std::string& name, int nClientVersion, const std::vector<std::string>& comments);
void AddTimeData(const CNetAddr& ip, int64 nTime);











/** Wrapped boost mutex: supports recursive locking, but no waiting  */
typedef boost::interprocess::interprocess_recursive_mutex CCriticalSection;

/** Wrapped boost mutex: supports waiting but not recursive locking */
typedef boost::interprocess::interprocess_mutex CWaitableCriticalSection;

#ifdef DEBUG_LOCKORDER
void EnterCritical(const char* pszName, const char* pszFile, int nLine, void* cs, bool fTry = false);
void LeaveCritical();
#else
void static inline EnterCritical(const char* pszName, const char* pszFile, int nLine, void* cs, bool fTry = false) {}
void static inline LeaveCritical() {}
#endif

/** Wrapper around boost::interprocess::scoped_lock */
template<typename Mutex>
class CMutexLock
{
private:
    boost::interprocess::scoped_lock<Mutex> lock;
public:

    void Enter(const char* pszName, const char* pszFile, int nLine)
    {
        if (!lock.owns())
        {
            EnterCritical(pszName, pszFile, nLine, (void*)(lock.mutex()));
#ifdef DEBUG_LOCKCONTENTION
            if (!lock.try_lock())
            {
                printf("LOCKCONTENTION: %s\n", pszName);
                printf("Locker: %s:%d\n", pszFile, nLine);
#endif
            lock.lock();
#ifdef DEBUG_LOCKCONTENTION
            }
#endif
        }
    }

    void Leave()
    {
        if (lock.owns())
        {
            lock.unlock();
            LeaveCritical();
        }
    }

    bool TryEnter(const char* pszName, const char* pszFile, int nLine)
    {
        if (!lock.owns())
        {
            EnterCritical(pszName, pszFile, nLine, (void*)(lock.mutex()), true);
            lock.try_lock();
            if (!lock.owns())
                LeaveCritical();
        }
        return lock.owns();
    }

    CMutexLock(Mutex& mutexIn, const char* pszName, const char* pszFile, int nLine, bool fTry = false) : lock(mutexIn, boost::interprocess::defer_lock)
    {
        if (fTry)
            TryEnter(pszName, pszFile, nLine);
        else
            Enter(pszName, pszFile, nLine);
    }

    ~CMutexLock()
    {
        if (lock.owns())
            LeaveCritical();
    }

    operator bool()
    {
        return lock.owns();
    }

    boost::interprocess::scoped_lock<Mutex> &GetLock()
    {
        return lock;
    }
};

typedef CMutexLock<CCriticalSection> CCriticalBlock;

#define LOCK(cs) CCriticalBlock criticalblock(cs, #cs, __FILE__, __LINE__)
#define LOCK2(cs1,cs2) CCriticalBlock criticalblock1(cs1, #cs1, __FILE__, __LINE__),criticalblock2(cs2, #cs2, __FILE__, __LINE__)
#define TRY_LOCK(cs,name) CCriticalBlock name(cs, #cs, __FILE__, __LINE__, true)

#define ENTER_CRITICAL_SECTION(cs) \
    { \
        EnterCritical(#cs, __FILE__, __LINE__, (void*)(&cs)); \
        (cs).lock(); \
    }

#define LEAVE_CRITICAL_SECTION(cs) \
    { \
        (cs).unlock(); \
        LeaveCritical(); \
    }

#ifdef MAC_OSX
// boost::interprocess::interprocess_semaphore seems to spinlock on OSX; prefer polling instead
class CSemaphore
{
private:
    CCriticalSection cs;
    int val;

public:
    CSemaphore(int init) : val(init) {}

    void wait() {
        do {
            {
                LOCK(cs);
                if (val>0) {
                    val--;
                    return;
                }
            }
            Sleep(100);
        } while(1);
    }

    bool try_wait() {
        LOCK(cs);
        if (val>0) {
            val--;
            return true;
        }
        return false;
    }

    void post() {
        LOCK(cs);
        val++;
    }
};
#else
typedef boost::interprocess::interprocess_semaphore CSemaphore;
#endif

inline std::string i64tostr(int64 n)
{
    return strprintf("%"PRI64d, n);
}

inline std::string itostr(int n)
{
    return strprintf("%d", n);
}

inline int64 atoi64(const char* psz)
{
#ifdef _MSC_VER
    return _atoi64(psz);
#else
    return strtoll(psz, NULL, 10);
#endif
}

inline int64 atoi64(const std::string& str)
{
#ifdef _MSC_VER
    return _atoi64(str.c_str());
#else
    return strtoll(str.c_str(), NULL, 10);
#endif
}

inline int atoi(const std::string& str)
{
    return atoi(str.c_str());
}

inline int roundint(double d)
{
    return (int)(d > 0 ? d + 0.5 : d - 0.5);
}

inline int64 roundint64(double d)
{
    return (int64)(d > 0 ? d + 0.5 : d - 0.5);
}

inline int64 abs64(int64 n)
{
    return (n >= 0 ? n : -n);
}

template<typename T>
std::string HexStr(const T itbegin, const T itend, bool fSpaces=false)
{
    std::vector<char> rv;
    static char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    rv.reserve((itend-itbegin)*3);
    for(T it = itbegin; it < itend; ++it)
    {
        unsigned char val = (unsigned char)(*it);
        if(fSpaces && it != itbegin)
            rv.push_back(' ');
        rv.push_back(hexmap[val>>4]);
        rv.push_back(hexmap[val&15]);
    }

    return std::string(rv.begin(), rv.end());
}

inline std::string HexStr(const std::vector<unsigned char>& vch, bool fSpaces=false)
{
    return HexStr(vch.begin(), vch.end(), fSpaces);
}

template<typename T>
void PrintHex(const T pbegin, const T pend, const char* pszFormat="%s", bool fSpaces=true)
{
    printf(pszFormat, HexStr(pbegin, pend, fSpaces).c_str());
}

inline void PrintHex(const std::vector<unsigned char>& vch, const char* pszFormat="%s", bool fSpaces=true)
{
    printf(pszFormat, HexStr(vch, fSpaces).c_str());
}

inline int64 GetPerformanceCounter()
{
    int64 nCounter = 0;
#ifdef WIN32
    QueryPerformanceCounter((LARGE_INTEGER*)&nCounter);
#else
    timeval t;
    gettimeofday(&t, NULL);
    nCounter = t.tv_sec * 1000000 + t.tv_usec;
#endif
    return nCounter;
}

inline int64 GetTimeMillis()
{
    return (boost::posix_time::ptime(boost::posix_time::microsec_clock::universal_time()) -
            boost::posix_time::ptime(boost::gregorian::date(1970,1,1))).total_milliseconds();
}

inline std::string DateTimeStrFormat(const char* pszFormat, int64 nTime)
{
    time_t n = nTime;
    struct tm* ptmTime = gmtime(&n);
    char pszTime[200];
    strftime(pszTime, sizeof(pszTime), pszFormat, ptmTime);
    return pszTime;
}

static const std::string strTimestampFormat = "%Y-%m-%d %H:%M:%S UTC";
inline std::string DateTimeStrFormat(int64 nTime)
{
    return DateTimeStrFormat(strTimestampFormat.c_str(), nTime);
}

template<typename T>
void skipspaces(T& it)
{
    while (isspace(*it))
        ++it;
}

inline bool IsSwitchChar(char c)
{
#ifdef WIN32
    return c == '-' || c == '/';
#else
    return c == '-';
#endif
}

/**
 * Return string argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (e.g. "1")
 * @return command-line argument or default value
 */
std::string GetArg(const std::string& strArg, const std::string& strDefault);
std::string GetPeercoinArg(const std::string& strArg, const std::string& strDefault);

/**
 * Return integer argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (e.g. 1)
 * @return command-line argument (0 if invalid number) or default value
 */
int64 GetArg(const std::string& strArg, int64 nDefault);
int64 GetPeercoinArg(const std::string& strArg, int64 nDefault);

/**
 * Return boolean argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (true or false)
 * @return command-line argument or default value
 */
bool GetBoolArg(const std::string& strArg, bool fDefault=false);
bool GetPeercoinBoolArg(const std::string& strArg, bool fDefault=false);

/**
 * Set an argument if it doesn't already have a value
 *
 * @param strArg Argument to set (e.g. "-foo")
 * @param strValue Value (e.g. "1")
 * @return true if argument gets set, false if it already had a value
 */
bool SoftSetArg(const std::string& strArg, const std::string& strValue);

/**
 * Set a boolean argument if it doesn't already have a value
 *
 * @param strArg Argument to set (e.g. "-foo")
 * @param fValue Value (e.g. false)
 * @return true if argument gets set, false if it already had a value
 */
bool SoftSetBoolArg(const std::string& strArg, bool fValue);









// Randomize the stack to help protect against buffer overrun exploits
#define IMPLEMENT_RANDOMIZE_STACK(ThreadFn)     \
    {                                           \
        static char nLoops;                     \
        if (nLoops <= 0)                        \
            nLoops = GetRand(20) + 1;           \
        if (nLoops-- > 1)                       \
        {                                       \
            ThreadFn;                           \
            return;                             \
        }                                       \
    }


template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1, typename T2, typename T3>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Update(&ctx, (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T>
uint256 SerializeHash(const T& obj, int nType=SER_GETHASH, int nVersion=PROTOCOL_VERSION)
{
    // Most of the time is spent allocating and deallocating CDataStream's
    // buffer.  If this ever needs to be optimized further, make a CStaticStream
    // class with its buffer on the stack.
    CDataStream ss(nType, nVersion);
    ss.reserve(10000);
    ss << obj;
    return Hash(ss.begin(), ss.end());
}

inline uint160 Hash160(const std::vector<unsigned char>& vch)
{
    uint256 hash1;
    SHA256(&vch[0], vch.size(), (unsigned char*)&hash1);
    uint160 hash2;
    RIPEMD160((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}


/** Median filter over a stream of values. 
 * Returns the median of the last N numbers
 */
template <typename T> class CMedianFilter
{
private:
    std::vector<T> vValues;
    std::vector<T> vSorted;
    unsigned int nSize;
public:
    CMedianFilter(unsigned int size, T initial_value):
        nSize(size)
    {
        vValues.reserve(size);
        vValues.push_back(initial_value);
        vSorted = vValues;
    }
    
    void input(T value)
    {
        if(vValues.size() == nSize)
        {
            vValues.erase(vValues.begin());
        }
        vValues.push_back(value);

        vSorted.resize(vValues.size());
        std::copy(vValues.begin(), vValues.end(), vSorted.begin());
        std::sort(vSorted.begin(), vSorted.end());
    }

    T median() const
    {
        int size = vSorted.size();
        assert(size>0);
        if(size & 1) // Odd number of elements
        {
            return vSorted[size/2];
        }
        else // Even number of elements
        {
            return (vSorted[size/2-1] + vSorted[size/2]) / 2;
        }
    }

    int size() const
    {
        return vValues.size();
    }

    std::vector<T> sorted () const
    {
        return vSorted;
    }
};










// Note: It turns out we might have been able to use boost::thread
// by using TerminateThread(boost::thread.native_handle(), 0);
#ifdef WIN32
typedef HANDLE bitcoin_pthread_t;

inline bitcoin_pthread_t CreateThread(void(*pfn)(void*), void* parg, bool fWantHandle=false)
{
    DWORD nUnused = 0;
    HANDLE hthread =
        CreateThread(
            NULL,                        // default security
            0,                           // inherit stack size from parent
            (LPTHREAD_START_ROUTINE)pfn, // function pointer
            parg,                        // argument
            0,                           // creation option, start immediately
            &nUnused);                   // thread identifier
    if (hthread == NULL)
    {
        printf("Error: CreateThread() returned %d\n", GetLastError());
        return (bitcoin_pthread_t)0;
    }
    if (!fWantHandle)
    {
        CloseHandle(hthread);
        return (bitcoin_pthread_t)-1;
    }
    return hthread;
}

inline void SetThreadPriority(int nPriority)
{
    SetThreadPriority(GetCurrentThread(), nPriority);
}
#else
inline pthread_t CreateThread(void(*pfn)(void*), void* parg, bool fWantHandle=false)
{
    pthread_t hthread = 0;
    int ret = pthread_create(&hthread, NULL, (void*(*)(void*))pfn, parg);
    if (ret != 0)
    {
        printf("Error: pthread_create() returned %d\n", ret);
        return (pthread_t)0;
    }
    if (!fWantHandle)
    {
        pthread_detach(hthread);
        return (pthread_t)-1;
    }
    return hthread;
}

#define THREAD_PRIORITY_LOWEST          PRIO_MAX
#define THREAD_PRIORITY_BELOW_NORMAL    2
#define THREAD_PRIORITY_NORMAL          0
#define THREAD_PRIORITY_ABOVE_NORMAL    0

inline void SetThreadPriority(int nPriority)
{
    // It's unclear if it's even possible to change thread priorities on Linux,
    // but we really and truly need it for the generation threads.
#ifdef PRIO_THREAD
    setpriority(PRIO_THREAD, 0, nPriority);
#else
    setpriority(PRIO_PROCESS, 0, nPriority);
#endif
}

inline void ExitThread(size_t nExitCode)
{
    pthread_exit((void*)nExitCode);
}
#endif





inline uint32_t ByteReverse(uint32_t value)
{
    value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
    return (value<<16) | (value>>16);
}

#endif
