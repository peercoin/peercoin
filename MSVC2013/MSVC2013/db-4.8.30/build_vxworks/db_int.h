/* DO NOT EDIT: automatically built by dist/s_vxworks. */
/*-
 * See the file LICENSE for redistribution information.
 *
 * Copyright (c) 1996-2009 Oracle.  All rights reserved.
 *
 * $Id$
 */

#ifndef _DB_INT_H_
#define	_DB_INT_H_

/*******************************************************
 * Berkeley DB ANSI/POSIX include files.
 *******************************************************/
#include "vxWorks.h"
#ifdef HAVE_SYSTEM_INCLUDE_FILES
#include <sys/types.h>
#ifdef DIAG_MVCC
#include <sys/mman.h>
#endif
#include <sys/stat.h>

#if defined(__INCLUDE_SELECT_H)
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_VXWORKS
#include <selectLib.h>
#endif
#endif

#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#ifdef HAVE_VXWORKS
#include <net/uio.h>
#else
#include <sys/uio.h>
#endif

#if defined(__INCLUDE_NETWORKING)
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

#if defined(STDC_HEADERS) || defined(__cplusplus)
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__INCLUDE_DIRECTORY)
#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif
#endif /* __INCLUDE_DIRECTORY */

#endif /* !HAVE_SYSTEM_INCLUDE_FILES */
#include "clib_port.h"
#include "db.h"

#ifdef DB_WIN32
#include "dbinc/win_db.h"
#endif

#include "db.h"
#include "clib_port.h"

#include "dbinc/queue.h"
#include "dbinc/shqueue.h"

#if defined(__cplusplus)
extern "C" {
#endif

/*******************************************************
 * Forward structure declarations.
 *******************************************************/
struct __db_reginfo_t;	typedef struct __db_reginfo_t REGINFO;
struct __db_txnhead;	typedef struct __db_txnhead DB_TXNHEAD;
struct __db_txnlist;	typedef struct __db_txnlist DB_TXNLIST;
struct __vrfy_childinfo;typedef struct __vrfy_childinfo VRFY_CHILDINFO;
struct __vrfy_dbinfo;   typedef struct __vrfy_dbinfo VRFY_DBINFO;
struct __vrfy_pageinfo; typedef struct __vrfy_pageinfo VRFY_PAGEINFO;

typedef SH_TAILQ_HEAD(__hash_head) DB_HASHTAB;

/*******************************************************
 * General purpose constants and macros.
 *******************************************************/
#undef	FALSE
#define	FALSE		0
#undef	TRUE
#define	TRUE		(!FALSE)

#define	MEGABYTE	1048576
#define	GIGABYTE	1073741824

#define	NS_PER_MS	1000000		/* Nanoseconds in a millisecond */
#define	NS_PER_US	1000		/* Nanoseconds in a microsecond */
#define	NS_PER_SEC	1000000000	/* Nanoseconds in a second */
#define	US_PER_MS	1000		/* Microseconds in a millisecond */
#define	US_PER_SEC	1000000		/* Microseconds in a second */
#define	MS_PER_SEC	1000		/* Milliseconds in a second */

#define	RECNO_OOB	0		/* Illegal record number. */

/* Test for a power-of-two (tests true for zero, which doesn't matter here). */
#define	POWER_OF_TWO(x)	(((x) & ((x) - 1)) == 0)

/* Test for valid page sizes. */
#define	DB_MIN_PGSIZE	0x000200	/* Minimum page size (512). */
#define	DB_MAX_PGSIZE	0x010000	/* Maximum page size (65536). */
#define	IS_VALID_PAGESIZE(x)						\
	(POWER_OF_TWO(x) && (x) >= DB_MIN_PGSIZE && ((x) <= DB_MAX_PGSIZE))

/* Minimum number of pages cached, by default. */
#define	DB_MINPAGECACHE	16

/*
 * If we are unable to determine the underlying filesystem block size, use
 * 8K on the grounds that most OS's use less than 8K for a VM page size.
 */
#define	DB_DEF_IOSIZE	(8 * 1024)

/* Align an integer to a specific boundary. */
#undef	DB_ALIGN
#define	DB_ALIGN(v, bound)						\
	(((v) + (bound) - 1) & ~(((uintmax_t)(bound)) - 1))

/* Increment a pointer to a specific boundary. */
#undef	ALIGNP_INC
#define	ALIGNP_INC(p, bound)						\
	(void *)(((uintptr_t)(p) + (bound) - 1) & ~(((uintptr_t)(bound)) - 1))

/*
 * Print an address as a u_long (a u_long is the largest type we can print
 * portably).  Most 64-bit systems have made longs 64-bits, so this should
 * work.
 */
#define	P_TO_ULONG(p)	((u_long)(uintptr_t)(p))

/*
 * Convert a pointer to a small integral value.
 *
 * The (u_int16_t)(uintptr_t) cast avoids warnings: the (uintptr_t) cast
 * converts the value to an integral type, and the (u_int16_t) cast converts
 * it to a small integral type so we don't get complaints when we assign the
 * final result to an integral type smaller than uintptr_t.
 */
#define	P_TO_UINT32(p)	((u_int32_t)(uintptr_t)(p))
#define	P_TO_UINT16(p)	((u_int16_t)(uintptr_t)(p))

/*
 * There are several on-page structures that are declared to have a number of
 * fields followed by a variable length array of items.  The structure size
 * without including the variable length array or the address of the first of
 * those elements can be found using SSZ.
 *
 * This macro can also be used to find the offset of a structure element in a
 * structure.  This is used in various places to copy structure elements from
 * unaligned memory references, e.g., pointers into a packed page.
 *
 * There are two versions because compilers object if you take the address of
 * an array.
 */
#undef	SSZ
#define	SSZ(name, field)  P_TO_UINT16(&(((name *)0)->field))

#undef	SSZA
#define	SSZA(name, field) P_TO_UINT16(&(((name *)0)->field[0]))

/* Structure used to print flag values. */
typedef struct __fn {
	u_int32_t mask;			/* Flag value. */
	const char *name;		/* Flag name. */
} FN;

/* Set, clear and test flags. */
#define	FLD_CLR(fld, f)		(fld) &= ~(f)
#define	FLD_ISSET(fld, f)	((fld) & (f))
#define	FLD_SET(fld, f)		(fld) |= (f)
#define	F_CLR(p, f)		(p)->flags &= ~(f)
#define	F_ISSET(p, f)		((p)->flags & (f))
#define	F_SET(p, f)		(p)->flags |= (f)
#define	LF_CLR(f)		((flags) &= ~(f))
#define	LF_ISSET(f)		((flags) & (f))
#define	LF_SET(f)		((flags) |= (f))

/*
 * Calculate a percentage.  The values can overflow 32-bit integer arithmetic
 * so we use floating point.
 *
 * When calculating a bytes-vs-page size percentage, we're getting the inverse
 * of the percentage in all cases, that is, we want 100 minus the percentage we
 * calculate.
 */
#define	DB_PCT(v, total)						\
	((int)((total) == 0 ? 0 : ((double)(v) * 100) / (total)))
#define	DB_PCT_PG(v, total, pgsize)					\
	((int)((total) == 0 ? 0 :					\
	    100 - ((double)(v) * 100) / (((double)total) * (pgsize))))

/*
 * Statistics update shared memory and so are expensive -- don't update the
 * values unless we're going to display the results.
 */
#undef	STAT
#ifdef	HAVE_STATISTICS
#define	STAT(x)	x
#else
#define	STAT(x)
#endif

/*
 * Structure used for callback message aggregation.
 *
 * Display values in XXX_stat_print calls.
 */
typedef struct __db_msgbuf {
	char *buf;			/* Heap allocated buffer. */
	char *cur;			/* Current end of message. */
	size_t len;			/* Allocated length of buffer. */
} DB_MSGBUF;
#define	DB_MSGBUF_INIT(a) do {						\
	(a)->buf = (a)->cur = NULL;					\
	(a)->len = 0;							\
} while (0)
#define	DB_MSGBUF_FLUSH(env, a) do {					\
	if ((a)->buf != NULL) {						\
		if ((a)->cur != (a)->buf)				\
			__db_msg(env, "%s", (a)->buf);		\
		__os_free(env, (a)->buf);				\
		DB_MSGBUF_INIT(a);					\
	}								\
} while (0)
#define	STAT_FMT(msg, fmt, type, v) do {				\
	DB_MSGBUF __mb;							\
	DB_MSGBUF_INIT(&__mb);						\
	__db_msgadd(env, &__mb, fmt, (type)(v));			\
	__db_msgadd(env, &__mb, "\t%s", msg);				\
	DB_MSGBUF_FLUSH(env, &__mb);					\
} while (0)
#define	STAT_HEX(msg, v)						\
	__db_msg(env, "%#lx\t%s", (u_long)(v), msg)
#define	STAT_ISSET(msg, p)						\
	__db_msg(env, "%sSet\t%s", (p) == NULL ? "!" : " ", msg)
#define	STAT_LONG(msg, v)						\
	__db_msg(env, "%ld\t%s", (long)(v), msg)
#define	STAT_LSN(msg, lsnp)						\
	__db_msg(env, "%lu/%lu\t%s",					\
	    (u_long)(lsnp)->file, (u_long)(lsnp)->offset, msg)
#define	STAT_POINTER(msg, v)						\
	__db_msg(env, "%#lx\t%s", P_TO_ULONG(v), msg)
#define	STAT_STRING(msg, p) do {					\
	const char *__p = p;	/* p may be a function call. */		\
	__db_msg(env, "%s\t%s", __p == NULL ? "!Set" : __p, msg);	\
} while (0)
#define	STAT_ULONG(msg, v)						\
	__db_msg(env, "%lu\t%s", (u_long)(v), msg)

/*
 * There are quite a few places in Berkeley DB where we want to initialize
 * a DBT from a string or other random pointer type, using a length typed
 * to size_t in most cases.  This macro avoids a lot of casting.  The macro
 * comes in two flavors because we often want to clear the DBT first.
 */
#define	DB_SET_DBT(dbt, d, s)  do {					\
	(dbt).data = (void *)(d);					\
	(dbt).size = (u_int32_t)(s);					\
} while (0)
#define	DB_INIT_DBT(dbt, d, s)  do {					\
	memset(&(dbt), 0, sizeof(dbt));					\
	DB_SET_DBT(dbt, d, s);						\
} while (0)

/*******************************************************
 * API return values
 *******************************************************/
/*
 * Return values that are OK for each different call.  Most calls have a
 * standard 'return of 0 is only OK value', but some, like db->get have
 * DB_NOTFOUND as a return value, but it really isn't an error.
 */
#define	DB_RETOK_STD(ret)	((ret) == 0)
#define	DB_RETOK_DBCDEL(ret)	((ret) == 0 || (ret) == DB_KEYEMPTY || \
				    (ret) == DB_NOTFOUND)
#define	DB_RETOK_DBCGET(ret)	((ret) == 0 || (ret) == DB_KEYEMPTY || \
				    (ret) == DB_NOTFOUND)
#define	DB_RETOK_DBCPUT(ret)	((ret) == 0 || (ret) == DB_KEYEXIST || \
				    (ret) == DB_NOTFOUND)
#define	DB_RETOK_DBDEL(ret)	DB_RETOK_DBCDEL(ret)
#define	DB_RETOK_DBGET(ret)	DB_RETOK_DBCGET(ret)
#define	DB_RETOK_DBPUT(ret)	((ret) == 0 || (ret) == DB_KEYEXIST)
#define	DB_RETOK_EXISTS(ret)	DB_RETOK_DBCGET(ret)
#define	DB_RETOK_LGGET(ret)	((ret) == 0 || (ret) == DB_NOTFOUND)
#define	DB_RETOK_MPGET(ret)	((ret) == 0 || (ret) == DB_PAGE_NOTFOUND)
#define	DB_RETOK_REPPMSG(ret)	((ret) == 0 || \
				    (ret) == DB_REP_IGNORE || \
				    (ret) == DB_REP_ISPERM || \
				    (ret) == DB_REP_NEWMASTER || \
				    (ret) == DB_REP_NEWSITE || \
				    (ret) == DB_REP_NOTPERM)
#define	DB_RETOK_REPMGR_START(ret) ((ret) == 0 || (ret) == DB_REP_IGNORE)

/* Find a reasonable operation-not-supported error. */
#ifdef	EOPNOTSUPP
#define	DB_OPNOTSUP	EOPNOTSUPP
#else
#ifdef	ENOTSUP
#define	DB_OPNOTSUP	ENOTSUP
#else
#define	DB_OPNOTSUP	EINVAL
#endif
#endif

/*******************************************************
 * Files.
 *******************************************************/
/*
 * We use 1024 as the maximum path length.  It's too hard to figure out what
 * the real path length is, as it was traditionally stored in <sys/param.h>,
 * and that file isn't always available.
 */
#define	DB_MAXPATHLEN	1024

#define	PATH_DOT	"."	/* Current working directory. */
				/* Path separator character(s). */
#define	PATH_SEPARATOR	"/\\"

/*******************************************************
 * Environment.
 *******************************************************/
/* Type passed to __db_appname(). */
typedef enum {
	DB_APP_NONE=0,			/* No type (region). */
	DB_APP_DATA,			/* Data file. */
	DB_APP_LOG,			/* Log file. */
	DB_APP_TMP,			/* Temporary file. */
	DB_APP_RECOVER			/* We are in recovery. */
} APPNAME;

/*
 * A set of macros to check if various functionality has been configured.
 *
 * ALIVE_ON	The is_alive function is configured.
 * CDB_LOCKING	CDB product locking.
 * CRYPTO_ON	Security has been configured.
 * LOCKING_ON	Locking has been configured.
 * LOGGING_ON	Logging has been configured.
 * MUTEX_ON	Mutexes have been configured.
 * MPOOL_ON	Memory pool has been configured.
 * REP_ON	Replication has been configured.
 * RPC_ON	RPC has been configured.
 * TXN_ON	Transactions have been configured.
 *
 * REP_ON is more complex than most: if the BDB library was compiled without
 * replication support, ENV->rep_handle will be NULL; if the BDB library has
 * replication support, but it was not configured, the region reference will
 * be NULL.
 */
#define	ALIVE_ON(env)		((env)->dbenv->is_alive != NULL)
#define	CDB_LOCKING(env)	F_ISSET(env, ENV_CDB)
#define	CRYPTO_ON(env)		((env)->crypto_handle != NULL)
#define	LOCKING_ON(env)		((env)->lk_handle != NULL)
#define	LOGGING_ON(env)		((env)->lg_handle != NULL)
#define	MPOOL_ON(env)		((env)->mp_handle != NULL)
#define	MUTEX_ON(env)		((env)->mutex_handle != NULL)
#define	REP_ON(env)							\
	((env)->rep_handle != NULL && (env)->rep_handle->region != NULL)
#define	RPC_ON(dbenv)		((dbenv)->cl_handle != NULL)
#define	TXN_ON(env)		((env)->tx_handle != NULL)

/*
 * STD_LOCKING	Standard locking, that is, locking was configured and CDB
 *		was not.  We do not do locking in off-page duplicate trees,
 *		so we check for that in the cursor first.
 */
#define	STD_LOCKING(dbc)						\
	(!F_ISSET(dbc, DBC_OPD) &&					\
	    !CDB_LOCKING((dbc)->env) && LOCKING_ON((dbc)->env))

/*
 * IS_RECOVERING: The system is running recovery.
 */
#define	IS_RECOVERING(env)						\
	(LOGGING_ON(env) && F_ISSET((env)->lg_handle, DBLOG_RECOVER))

/* Initialization methods are often illegal before/after open is called. */
#define	ENV_ILLEGAL_AFTER_OPEN(env, name)				\
	if (F_ISSET((env), ENV_OPEN_CALLED))				\
		return (__db_mi_open(env, name, 1));
#define	ENV_ILLEGAL_BEFORE_OPEN(env, name)				\
	if (!F_ISSET((env), ENV_OPEN_CALLED))				\
		return (__db_mi_open(env, name, 0));

/* We're not actually user hostile, honest. */
#define	ENV_REQUIRES_CONFIG(env, handle, i, flags)			\
	if (handle == NULL)						\
		return (__env_not_config(env, i, flags));
#define	ENV_REQUIRES_CONFIG_XX(env, handle, i, flags)			\
	if ((env)->handle->region == NULL)				\
		return (__env_not_config(env, i, flags));
#define	ENV_NOT_CONFIGURED(env, handle, i, flags)			\
	if (F_ISSET((env), ENV_OPEN_CALLED))				\
		ENV_REQUIRES_CONFIG(env, handle, i, flags)

#define	ENV_ENTER(env, ip) do {						\
	int __ret;							\
	PANIC_CHECK(env);						\
	if ((env)->thr_hashtab == NULL)					\
		ip = NULL;						\
	else {								\
		if ((__ret =						\
		    __env_set_state(env, &(ip), THREAD_ACTIVE)) != 0)	\
			return (__ret);					\
	}								\
} while (0)

#define	FAILCHK_THREAD(env, ip) do {					\
	if ((ip) != NULL)						\
		(ip)->dbth_state = THREAD_FAILCHK;			\
} while (0)

#define	ENV_GET_THREAD_INFO(env, ip) ENV_ENTER(env, ip)

#ifdef DIAGNOSTIC
#define	ENV_LEAVE(env, ip) do {						\
	if ((ip) != NULL) {						\
		DB_ASSERT(env, ((ip)->dbth_state == THREAD_ACTIVE  ||	\
		    (ip)->dbth_state == THREAD_FAILCHK));		\
		(ip)->dbth_state = THREAD_OUT;				\
	}								\
} while (0)
#else
#define	ENV_LEAVE(env, ip) do {						\
	if ((ip) != NULL)						\
		(ip)->dbth_state = THREAD_OUT;				\
} while (0)
#endif
#ifdef DIAGNOSTIC
#define	CHECK_THREAD(env) do {						\
	if ((env)->thr_hashtab != NULL)					\
		(void)__env_set_state(env, NULL, THREAD_VERIFY);	\
} while (0)
#ifdef HAVE_STATISTICS
#define	CHECK_MTX_THREAD(env, mtx) do {					\
	if (mtx->alloc_id != MTX_MUTEX_REGION &&			\
	    mtx->alloc_id != MTX_ENV_REGION &&				\
	    mtx->alloc_id != MTX_APPLICATION)				\
		CHECK_THREAD(env);					\
} while (0)
#else
#define	CHECK_MTX_THREAD(env, mtx)
#endif
#else
#define	CHECK_THREAD(env)
#define	CHECK_MTX_THREAD(env, mtx)
#endif

typedef enum {
	THREAD_SLOT_NOT_IN_USE=0,
	THREAD_OUT,
	THREAD_ACTIVE,
	THREAD_BLOCKED,
	THREAD_BLOCKED_DEAD,
	THREAD_FAILCHK,
	THREAD_VERIFY
} DB_THREAD_STATE;

typedef struct __pin_list {
	roff_t b_ref;		/* offset to buffer. */
	int region;		/* region containing buffer. */
} PIN_LIST;
#define	PINMAX 4

struct __db_thread_info {
	pid_t		dbth_pid;
	db_threadid_t	dbth_tid;
	DB_THREAD_STATE	dbth_state;
	SH_TAILQ_ENTRY	dbth_links;
	/*
	 * The following fields track which buffers this thread of
	 * control has pinned in the mpool buffer cache.
	 */
	u_int16_t	dbth_pincount;	/* Number of pins for this thread. */
	u_int16_t	dbth_pinmax;	/* Number of slots allocated. */
	roff_t		dbth_pinlist;	/* List of pins. */
	PIN_LIST	dbth_pinarray[PINMAX];	/* Initial array of slots. */
};

typedef struct __env_thread_info {
	u_int32_t	thr_count;
	u_int32_t	thr_max;
	u_int32_t	thr_nbucket;
	roff_t		thr_hashoff;
} THREAD_INFO;

#define	DB_EVENT(env, e, einfo) do {					\
	DB_ENV *__dbenv = (env)->dbenv;					\
	if (__dbenv->db_event_func != NULL)				\
		__dbenv->db_event_func(__dbenv, e, einfo);		\
} while (0)

typedef struct __flag_map {
	u_int32_t inflag, outflag;
} FLAG_MAP;

/*
 * Internal database environment structure.
 *
 * This is the private database environment handle.  The public environment
 * handle is the DB_ENV structure.   The library owns this structure, the user
 * owns the DB_ENV structure.  The reason there are two structures is because
 * the user's configuration outlives any particular DB_ENV->open call, and
 * separate structures allows us to easily discard internal information without
 * discarding the user's configuration.
 */
struct __env {
	DB_ENV *dbenv;			/* Linked DB_ENV structure */

	/*
	 * The ENV structure can be used concurrently, so field access is
	 * protected.
	 */
	db_mutex_t mtx_env;		/* ENV structure mutex */

	/*
	 * Some fields are included in the ENV structure rather than in the
	 * DB_ENV structure because they are only set as arguments to the
	 * DB_ENV->open method.  In other words, because of the historic API,
	 * not for any rational reason.
	 *
	 * Arguments to DB_ENV->open.
	 */
	char	 *db_home;		/* Database home */
	u_int32_t open_flags;		/* Flags */
	int	  db_mode;		/* Default open permissions */

	pid_t	pid_cache;		/* Cached process ID */

	DB_FH	*lockfhp;		/* fcntl(2) locking file handle */

	DB_LOCKER *env_lref;		/* Locker in non-threaded handles */

	DB_DISTAB   recover_dtab;	/* Dispatch table for recover funcs */

	int dir_mode;			/* Intermediate directory perms. */

	/* Thread tracking */
	u_int32_t	 thr_nbucket;	/* Number of hash buckets */
	DB_HASHTAB	*thr_hashtab;	/* Hash table of DB_THREAD_INFO */

	/* Mutex allocation */
	struct {
		int	  alloc_id;	/* Allocation ID argument */
		u_int32_t flags;	/* Flags argument */
	} *mutex_iq;			/* Initial mutexes queue */
	u_int		mutex_iq_next;	/* Count of initial mutexes */
	u_int		mutex_iq_max;	/* Maximum initial mutexes */

	/*
	 * List of open DB handles for this ENV, used for cursor
	 * adjustment.  Must be protected for multi-threaded support.
	 */
	db_mutex_t mtx_dblist;
	int	   db_ref;		/* DB handle reference count */
	TAILQ_HEAD(__dblist, __db) dblist;

	/*
	 * List of open file handles for this ENV.  Must be protected
	 * for multi-threaded support.
	 */
	TAILQ_HEAD(__fdlist, __fh_t) fdlist;

	db_mutex_t	 mtx_mt;	/* Mersenne Twister mutex */
	int		 mti;		/* Mersenne Twister index */
	u_long		*mt;		/* Mersenne Twister state vector */

	DB_CIPHER	*crypto_handle;	/* Crypto handle */
	DB_LOCKTAB	*lk_handle;	/* Lock handle */
	DB_LOG		*lg_handle;	/* Log handle */
	DB_MPOOL	*mp_handle;	/* Mpool handle */
	DB_MUTEXMGR	*mutex_handle;	/* Mutex handle */
	DB_REP		*rep_handle;	/* Replication handle */
	DB_TXNMGR	*tx_handle;	/* Txn handle */

	/* Application callback to copy data to/from a custom data source */
#define	DB_USERCOPY_GETDATA	0x0001
#define	DB_USERCOPY_SETDATA	0x0002
	int (*dbt_usercopy)
	    __P((DBT *, u_int32_t, void *, u_int32_t, u_int32_t));

	REGINFO	*reginfo;		/* REGINFO structure reference */

#define	DB_TEST_ELECTINIT	 1	/* after __rep_elect_init */
#define	DB_TEST_ELECTVOTE1	 2	/* after sending VOTE1 */
#define	DB_TEST_POSTDESTROY	 3	/* after destroy op */
#define	DB_TEST_POSTLOG		 4	/* after logging all pages */
#define	DB_TEST_POSTLOGMETA	 5	/* after logging meta in btree */
#define	DB_TEST_POSTOPEN	 6	/* after __os_open */
#define	DB_TEST_POSTSYNC	 7	/* after syncing the log */
#define	DB_TEST_PREDESTROY	 8	/* before destroy op */
#define	DB_TEST_PREOPEN		 9	/* before __os_open */
#define	DB_TEST_SUBDB_LOCKS	 10	/* subdb locking tests */
	int	test_abort;		/* Abort value for testing */
	int	test_check;		/* Checkpoint value for testing */
	int	test_copy;		/* Copy value for testing */

#define	ENV_CDB			0x00000001 /* DB_INIT_CDB */
#define	ENV_DBLOCAL		0x00000002 /* Environment for a private DB */
#define	ENV_LITTLEENDIAN	0x00000004 /* Little endian system. */
#define	ENV_LOCKDOWN		0x00000008 /* DB_LOCKDOWN set */
#define	ENV_NO_OUTPUT_SET	0x00000010 /* No output channel set */
#define	ENV_OPEN_CALLED		0x00000020 /* DB_ENV->open called */
#define	ENV_PRIVATE		0x00000040 /* DB_PRIVATE set */
#define	ENV_RECOVER_FATAL	0x00000080 /* Doing fatal recovery in env */
#define	ENV_REF_COUNTED		0x00000100 /* Region references this handle */
#define	ENV_SYSTEM_MEM		0x00000200 /* DB_SYSTEM_MEM set */
#define	ENV_THREAD		0x00000400 /* DB_THREAD set */
	u_int32_t flags;
};

/*******************************************************
 * Database Access Methods.
 *******************************************************/
/*
 * DB_IS_THREADED --
 *	The database handle is free-threaded (was opened with DB_THREAD).
 */
#define	DB_IS_THREADED(dbp)						\
	((dbp)->mutex != MUTEX_INVALID)

/* Initialization methods are often illegal before/after open is called. */
#define	DB_ILLEGAL_AFTER_OPEN(dbp, name)				\
	if (F_ISSET((dbp), DB_AM_OPEN_CALLED))				\
		return (__db_mi_open((dbp)->env, name, 1));
#define	DB_ILLEGAL_BEFORE_OPEN(dbp, name)				\
	if (!F_ISSET((dbp), DB_AM_OPEN_CALLED))				\
		return (__db_mi_open((dbp)->env, name, 0));
/* Some initialization methods are illegal if environment isn't local. */
#define	DB_ILLEGAL_IN_ENV(dbp, name)					\
	if (!F_ISSET((dbp)->env, ENV_DBLOCAL))				\
		return (__db_mi_env((dbp)->env, name));
#define	DB_ILLEGAL_METHOD(dbp, flags) {					\
	int __ret;							\
	if ((__ret = __dbh_am_chk(dbp, flags)) != 0)			\
		return (__ret);						\
}

/*
 * Common DBC->internal fields.  Each access method adds additional fields
 * to this list, but the initial fields are common.
 */
#define	__DBC_INTERNAL							\
	DBC	 *opd;			/* Off-page duplicate cursor. */\
	DBC	 *pdbc;			/* Pointer to parent cursor. */ \
									\
	void	 *page;			/* Referenced page. */		\
	u_int32_t part;			/* Partition number. */		\
	db_pgno_t root;			/* Tree root. */		\
	db_pgno_t pgno;			/* Referenced page number. */	\
	db_indx_t indx;			/* Referenced key item index. */\
									\
	/* Streaming -- cache last position. */				\
	db_pgno_t stream_start_pgno;	/* Last start pgno. */		\
	u_int32_t stream_off;		/* Current offset. */		\
	db_pgno_t stream_curr_pgno;	/* Current overflow page. */	\
									\
	DB_LOCK		lock;		/* Cursor lock. */		\
	db_lockmode_t	lock_mode;	/* Lock mode. */

struct __dbc_internal {
	__DBC_INTERNAL
};

/* Actions that __db_master_update can take. */
typedef enum { MU_REMOVE, MU_RENAME, MU_OPEN } mu_action;

/*
 * Access-method-common macro for determining whether a cursor
 * has been initialized.
 */
#ifdef HAVE_PARTITION
#define	IS_INITIALIZED(dbc)	(DB_IS_PARTITIONED((dbc)->dbp) ?	\
		((PART_CURSOR *)(dbc)->internal)->sub_cursor != NULL && \
		((PART_CURSOR *)(dbc)->internal)->sub_cursor->		\
		    internal->pgno != PGNO_INVALID :			\
		(dbc)->internal->pgno != PGNO_INVALID)
#else
#define	IS_INITIALIZED(dbc)	((dbc)->internal->pgno != PGNO_INVALID)
#endif

/* Free the callback-allocated buffer, if necessary, hanging off of a DBT. */
#define	FREE_IF_NEEDED(env, dbt)					\
	if (F_ISSET((dbt), DB_DBT_APPMALLOC)) {				\
		__os_ufree((env), (dbt)->data);				\
		F_CLR((dbt), DB_DBT_APPMALLOC);				\
	}

/*
 * Use memory belonging to object "owner" to return the results of
 * any no-DBT-flag get ops on cursor "dbc".
 */
#define	SET_RET_MEM(dbc, owner)				\
	do {						\
		(dbc)->rskey = &(owner)->my_rskey;	\
		(dbc)->rkey = &(owner)->my_rkey;	\
		(dbc)->rdata = &(owner)->my_rdata;	\
	} while (0)

/* Use the return-data memory src is currently set to use in dest as well. */
#define	COPY_RET_MEM(src, dest)				\
	do {						\
		(dest)->rskey = (src)->rskey;		\
		(dest)->rkey = (src)->rkey;		\
		(dest)->rdata = (src)->rdata;		\
	} while (0)

/* Reset the returned-memory pointers to their defaults. */
#define	RESET_RET_MEM(dbc)				\
	do {						\
		(dbc)->rskey = &(dbc)->my_rskey;	\
		(dbc)->rkey = &(dbc)->my_rkey;		\
		(dbc)->rdata = &(dbc)->my_rdata;	\
	} while (0)

/*******************************************************
 * Mpool.
 *******************************************************/
/*
 * File types for DB access methods.  Negative numbers are reserved to DB.
 */
#define	DB_FTYPE_SET		-1		/* Call pgin/pgout functions. */
#define	DB_FTYPE_NOTSET		 0		/* Don't call... */
#define	DB_LSN_OFF_NOTSET	-1		/* Not yet set. */
#define	DB_CLEARLEN_NOTSET	UINT32_MAX	/* Not yet set. */

/* Structure used as the DB pgin/pgout pgcookie. */
typedef struct __dbpginfo {
	size_t	db_pagesize;		/* Underlying page size. */
	u_int32_t flags;		/* Some DB_AM flags needed. */
	DBTYPE  type;			/* DB type */
} DB_PGINFO;

/*******************************************************
 * Log.
 *******************************************************/
/* Initialize an LSN to 'zero'. */
#define	ZERO_LSN(LSN) do {						\
	(LSN).file = 0;							\
	(LSN).offset = 0;						\
} while (0)
#define	IS_ZERO_LSN(LSN)	((LSN).file == 0 && (LSN).offset == 0)

#define	IS_INIT_LSN(LSN)	((LSN).file == 1 && (LSN).offset == 0)
#define	INIT_LSN(LSN)		do {					\
	(LSN).file = 1;							\
	(LSN).offset = 0;						\
} while (0)

#define	MAX_LSN(LSN) do {						\
	(LSN).file = UINT32_MAX;					\
	(LSN).offset = UINT32_MAX;					\
} while (0)
#define	IS_MAX_LSN(LSN) \
	((LSN).file == UINT32_MAX && (LSN).offset == UINT32_MAX)

/* If logging is turned off, smash the lsn. */
#define	LSN_NOT_LOGGED(LSN) do {					\
	(LSN).file = 0;							\
	(LSN).offset = 1;						\
} while (0)
#define	IS_NOT_LOGGED_LSN(LSN) \
	((LSN).file == 0 && (LSN).offset == 1)

/*
 * LOG_COMPARE -- compare two LSNs.
 */

#define	LOG_COMPARE(lsn0, lsn1)						\
    ((lsn0)->file != (lsn1)->file ?					\
    ((lsn0)->file < (lsn1)->file ? -1 : 1) :				\
    ((lsn0)->offset != (lsn1)->offset ?					\
    ((lsn0)->offset < (lsn1)->offset ? -1 : 1) : 0))

/*******************************************************
 * Txn.
 *******************************************************/
#define	DB_NONBLOCK(C)	((C)->txn != NULL && F_ISSET((C)->txn, TXN_NOWAIT))
#define	NOWAIT_FLAG(txn) \
	((txn) != NULL && F_ISSET((txn), TXN_NOWAIT) ? DB_LOCK_NOWAIT : 0)
#define	IS_REAL_TXN(txn)						\
	((txn) != NULL && !F_ISSET(txn, TXN_CDSGROUP))
#define	IS_SUBTRANSACTION(txn)						\
	((txn) != NULL && (txn)->parent != NULL)

/*******************************************************
 * Crypto.
 *******************************************************/
#define	DB_IV_BYTES     16		/* Bytes per IV */
#define	DB_MAC_KEY	20		/* Bytes per MAC checksum */

/*******************************************************
 * Compression
 *******************************************************/
#define CMP_INT_SPARE_VAL	0xFC	/* Smallest byte value that the integer
					   compression algorithm doesn't use */

/*******************************************************
 * Secondaries over RPC.
 *******************************************************/
#ifdef CONFIG_TEST
/*
 * These are flags passed to DB->associate calls by the Tcl API if running
 * over RPC.  The RPC server will mask out these flags before making the real
 * DB->associate call.
 *
 * These flags must coexist with the valid flags to DB->associate (currently
 * DB_AUTO_COMMIT and DB_CREATE).  DB_AUTO_COMMIT is in the group of
 * high-order shared flags (0xff000000), and DB_CREATE is in the low-order
 * group (0x00000fff), so we pick a range in between.
 */
#define	DB_RPC2ND_MASK		0x00f00000 /* Reserved bits. */

#define	DB_RPC2ND_REVERSEDATA	0x00100000 /* callback_n(0) _s_reversedata. */
#define	DB_RPC2ND_NOOP		0x00200000 /* callback_n(1) _s_noop */
#define	DB_RPC2ND_CONCATKEYDATA	0x00300000 /* callback_n(2) _s_concatkeydata */
#define	DB_RPC2ND_CONCATDATAKEY 0x00400000 /* callback_n(3) _s_concatdatakey */
#define	DB_RPC2ND_REVERSECONCAT	0x00500000 /* callback_n(4) _s_reverseconcat */
#define	DB_RPC2ND_TRUNCDATA	0x00600000 /* callback_n(5) _s_truncdata */
#define	DB_RPC2ND_CONSTANT	0x00700000 /* callback_n(6) _s_constant */
#define	DB_RPC2ND_GETZIP	0x00800000 /* sj_getzip */
#define	DB_RPC2ND_GETNAME	0x00900000 /* sj_getname */
#endif

#if defined(__cplusplus)
}
#endif

/*******************************************************
 * Remaining general DB includes.
 *******************************************************/


#include "dbinc/globals.h"
#include "dbinc/clock.h"
#include "dbinc/debug.h"
#include "dbinc/region.h"
#include "dbinc_auto/env_ext.h"
#include "dbinc/mutex.h"
#ifdef HAVE_REPLICATION_THREADS
#include "dbinc/repmgr.h"
#endif
#include "dbinc/rep.h"
#include "dbinc/os.h"
#include "dbinc_auto/clib_ext.h"
#include "dbinc_auto/common_ext.h"

/*******************************************************
 * Remaining Log.
 * These need to be defined after the general includes
 * because they need rep.h from above.
 *******************************************************/
/*
 * Test if the environment is currently logging changes.  If we're in recovery
 * or we're a replication client, we don't need to log changes because they're
 * already in the log, even though we have a fully functional log system.
 */
#define	DBENV_LOGGING(env)						\
	(LOGGING_ON(env) && !IS_REP_CLIENT(env) && (!IS_RECOVERING(env)))

/*
 * Test if we need to log a change.  By default, we don't log operations without
 * associated transactions, unless DIAGNOSTIC, DEBUG_ROP or DEBUG_WOP are on.
 * This is because we want to get log records for read/write operations, and, if
 * we are trying to debug something, more information is always better.
 *
 * The DBC_RECOVER flag is set when we're in abort, as well as during recovery;
 * thus DBC_LOGGING may be false for a particular dbc even when DBENV_LOGGING
 * is true.
 *
 * We explicitly use LOGGING_ON/IS_REP_CLIENT here because we don't want to pull
 * in the log headers, which IS_RECOVERING (and thus DBENV_LOGGING) rely on, and
 * because DBC_RECOVER should be set anytime IS_RECOVERING would be true.
 *
 * If we're not in recovery (master - doing an abort or a client applying
 * a txn), then a client's only path through here is on an internal
 * operation, and a master's only path through here is a transactional
 * operation.  Detect if either is not the case.
 */
#if defined(DIAGNOSTIC) || defined(DEBUG_ROP)  || defined(DEBUG_WOP)
#define	DBC_LOGGING(dbc)	__dbc_logging(dbc)
#else
#define	DBC_LOGGING(dbc)						\
	((dbc)->txn != NULL && LOGGING_ON((dbc)->env) &&		\
	    !F_ISSET((dbc), DBC_RECOVER) && !IS_REP_CLIENT((dbc)->env))
#endif

#endif /* !_DB_INT_H_ */
