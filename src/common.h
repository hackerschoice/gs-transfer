
#ifndef __GST_COMMON_H__
#define __GST_COMMON_H__ 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <libgen.h>		/* basename() */
#include <openssl/ssl.h>
#include "gsocket.h"
#include "gs-utils.h"

#define GST_SECRET_MAX_LEN		(256 / 8)	/* Maximum lengh in bytes */
#define GST_READ_BUF_SIZE		(4 * 2048)		/* Single read buffer size (from file) */
#define GST_DFL_CIPHER			"SRP-AES-256-CBC-SHA"
#define GST_DFL_STRENGTH		"4096"

struct _gopt
{
	GS_CTX gs_ctx;
	GS *gsocket;

	SSL_CTX *ssl_ctx;
	SSL *ssl;
	int flags;
	int verboselevel;
	char *sec_str;
	char *sec_file;
	GS_ADDR srp_secret;
	GS_ADDR gs_addr;

	FILE *out;			/* Normally 'stdout' unless -O */

	int n_files;
	char **files;
};

#define GST_FL_IS_SERVER		(0x01)
#define GST_FL_IS_MULTI_SERVER	(0x02)
#define GST_FL_STDOUT			(0x04)


extern struct _gopt gopt;

#ifndef MAX
# define MAX(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

#ifndef MIN
# define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#ifdef DEBUG
# define DEBUGF(a...) do{fprintf(stderr, "DEBUG %s:%d: ", __func__, __LINE__); fprintf(stderr, a); }while(0)
#else
# define DEBUGF(a...)
#endif

#define VOUT(level, a...) do { \
	if (level > gopt.verboselevel) \
		break; \
	fprintf(gopt.out, a); \
} while (0)

#define XFREE(ptr)  do{if(ptr) free(ptr); ptr = NULL;}while(0)

#define ERREXIT(a...)   do { \
		fprintf(stderr, "ERROR "); \
        fprintf(stderr, "%s():%d ", __func__, __LINE__); \
        fprintf(stderr, a); \
        exit(-1); \
} while (0)

#ifndef XASSERT
# define XASSERT(expr, a...) do { \
	if (!(expr)) { \
		fprintf(stderr, "%s:%d:%s() ASSERT(%s) ", __FILE__, __LINE__, __func__, #expr); \
		fprintf(stderr, a); \
		fprintf(stderr, " Exiting...\n"); \
		exit(255); \
	} \
} while (0)
#endif

#ifdef DEBUG
# define HEXDUMP(a, len)        do { \
        int n = 0; \
        fprintf(stderr, "%s:%d HEX ", __FILE__, __LINE__); \
        while (n < len) fprintf(stderr, "%2.2x", ((unsigned char *)a)[n++]); \
        fprintf(stderr, "\n"); \
} while (0)
#else
# define HEXDUMP(a, len)
#endif

#endif /* !__GST_COMMON_H__ */
