
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <netdb.h>		// gethostbyname
#include "gsocket.h"
#include "gs-utils.h"

#ifdef DEBUG
# define WITH_DEBUG
#endif
// #define WITH_DEBUG

#define GS_NET_DEFAULT_HOST			"gs.thc.org"
#define GS_NET_DEFAULT_PORT			7350
#ifdef WITH_DEBUG
# define GS_DEFAULT_PING_INTERVAL	(600)
#else
# define GS_DEFAULT_PING_INTERVAL	(60)
#endif

#ifndef MAX
# define MAX(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

#ifndef MIN
# define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#ifdef WITH_DEBUG
# define DEBUGF(a...)   do { \
        fprintf(stderr, "%s:%d ", __FILE__, __LINE__); \
        fprintf(stderr, a); \
        fflush(stderr); \
} while (0)
#else
# define DEBUGF(a...)   do { } while (0)
#endif

#define ERREXIT(a...)   do { \
        fprintf(stderr, "%s():%d ", __func__, __LINE__); \
        fprintf(stderr, a); \
        exit(-1); \
} while (0)

#define XFREE(aptr)		do { \
	if (aptr == NULL) \
		break; \
	free(aptr); \
	aptr = NULL; \
} while (0)

#ifdef WITH_DEBUG
# define HEXDUMP(a, len)        do { \
        int n = 0; \
        fprintf(stderr, "%s:%d HEX (%lu) ", __FILE__, __LINE__, len); \
        while (n < len) fprintf(stderr, "%2.2x", ((unsigned char *)a)[n++]); \
        fprintf(stderr, "\n"); \
} while (0)
#else
# define HEXDUMP(a, len)	do { } while (0)
#endif

static int gs_pkt_listen_write(GS *gsocket, struct gs_sox *sox);
static int gs_pkt_connect_write(GS *gsocket, struct gs_sox *sox);


#ifndef int_ntoa
const char *
int_ntoa(uint32_t ip)
{
	struct in_addr in;

	in.s_addr = ip;
	return inet_ntoa(in);
}
#endif

#define gs_set_error(gs_ctx, a...)	do { \
	snprintf(gs_ctx->err_buf, sizeof (gs_ctx)->err_buf, a); \
} while (0)

int
GS_CTX_init(GS_CTX *ctx, fd_set *rfd, fd_set *wfd)
{
	memset(ctx, 0, sizeof *ctx);

	ctx->rfd = rfd;
	ctx->wfd = wfd;
	if (ctx->rfd == NULL)
	{
		ctx->rfd = calloc(1, sizeof *ctx->rfd);
		ctx->wfd = calloc(1, sizeof *ctx->wfd);
		ctx->flags |= GS_CTX_FL_RFD_INTERNAL;
	} 

	return 0;
}

int
GS_CTX_free(GS_CTX *ctx)
{
	if (ctx->flags & GS_CTX_FL_RFD_INTERNAL)
	{
		XFREE(ctx->rfd);
		XFREE(ctx->wfd);
	}

	memset(ctx, 0, sizeof *ctx);

	return 0;
}

static uint32_t
hostname_to_ip(char *hostname)
{
	struct hostent *he;
	struct in_addr **addr_list;

	he = gethostbyname(hostname);
	if (he == NULL)
		return 0xFFFFFFFF;

	addr_list = (struct in_addr **)he->h_addr_list;
	if (addr_list == NULL)
		return 0xFFFFFFFF;
	if (addr_list[0] == NULL)
		return 0xFFFFFFFF;

	return addr_list[0][0].s_addr;
}

GS *
GS_new(GS_CTX *ctx, GS_ADDR *addr)
{
	GS *gsocket = NULL;
	char *ptr;
	char *hostname;

	gsocket = calloc(1, sizeof *gsocket);
	if (gsocket == NULL)
		return NULL;

	/* FIXME: net.addr should be dependent on *addr to support load balancing:
	 * - select one of 26 servers based on addr % 26.
	 */	
	ptr = getenv("GSOCKET_PORT");
	if (ptr != NULL)
		gsocket->net.port = htons(atoi(ptr));
	else
		gsocket->net.port = htons(GS_NET_DEFAULT_PORT);

	ptr = getenv("GSOCKET_IP");
	if (ptr != NULL)
	{
		gsocket->net.addr = inet_addr(ptr);
	} else {
		char buf[256];
		hostname = getenv("GSOCKET_HOST");
		if (hostname == NULL)
		{
			/* Connect to [a-z].gsocket.org */
			int num = 0;
			for (int i = 0; i < sizeof addr->addr; i++)
				num += addr->addr[i];
			num = num % 26;
			snprintf(buf, sizeof buf, "%c.%s", 'a' + num, GS_NET_DEFAULT_HOST);
			hostname = buf;
		}

		uint32_t ip;
		ip = hostname_to_ip(hostname);
		if (ip == 0xFFFFFFFF)
		{
			free(gsocket);
			gs_set_error(ctx, "Failed to resolve '%s'", hostname);
			return NULL;
		}
		gsocket->net.addr = ip;
	}
	gsocket->net.fd_accepted = -1;

	gsocket->ctx = ctx;

	gsocket->net.n_sox = 5;

	gsocket->flags |= GS_FL_NONBLOCKING;	/* non-blocking by default */

	memcpy(&gsocket->gs_addr, addr, sizeof gsocket->gs_addr);

	return gsocket;
}

/*
 * First and completing call to 'connect()' (non-blocking).
 * Return -2 on error (fatal, must exit)
 * Return -1 if in progress
 * Return 0 on success (connection actually established)
 */
static int
gs_net_connect_by_sox(GS *gsocket, struct gs_sox *sox)
{
	struct sockaddr_in addr;
	int ret;
	// GS_CTX *gs_ctx = gsocket->ctx;
	
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = gsocket->net.addr;
	addr.sin_port = gsocket->net.port;
	ret = connect(sox->fd, (struct sockaddr *)&addr, sizeof addr);
	DEBUGF("connect(%s, fd = %d): %d (errno = %d)\n", int_ntoa(gsocket->net.addr), sox->fd, ret, errno);
	if (ret != 0)
	{
		if (errno == EINPROGRESS)
		{
			// FD_SET(sox->fd, gs_ctx->wfd);
			// FD_CLR(sox->fd, gs_ctx->rfd);
			sox->flags |= GS_SOX_WANT_WRITE;
			sox->state = GS_STATE_SYS_CONNECT;

			return -1;
		}
		if (errno != EISCONN)
		{
			gs_set_error(gsocket->ctx, "connect(%s:%d)", int_ntoa(gsocket->net.addr), ntohs(gsocket->net.port));
			return -2;
		}
	}
	DEBUGF("connect() SUCCESS\n");

	/* SUCCESSFULLY connected */
	sox->state = GS_STATE_SYS_NONE;
	sox->flags &= ~GS_SOX_WANT_WRITE;
	gsocket->net.conn_count += 1;

	if (gsocket->flags & GS_FL_IS_CLIENT)
		gs_pkt_connect_write(gsocket, sox);
	else
		gs_pkt_listen_write(gsocket, sox);

	if (gsocket->net.conn_count >= gsocket->net.n_sox)
		gsocket->flags |= GS_FL_TCP_CONNECTED;

	return 0;
}

/*
 * Return > 0 on success.
 * Return 0 if write would block.
 * Return -1 on error.
  */
static int
gs_write(struct gs_sox *sox, const void *data, size_t len)
{
	int ret;

	ret = write(sox->fd, data, len);
	if (ret == len)
	{
		sox->flags &= ~GS_SOX_WANT_WRITE;
		return len;
	}
	if (ret > 0)
		ERREXIT("Fatal, partial write() should not happen.\n");

	if (errno != EAGAIN)
		return -1;

	/* EAGAIN */
	sox->flags |= GS_SOX_WANT_WRITE;
	memcpy(sox->wbuf, data, len);
	sox->wlen = len;

	return 0;
}

static int
gs_pkt_ping_write(GS *gsocket, struct gs_sox *sox)
{
	int ret;

	DEBUGF("### PKT PING write()\n");

	/* Do not send PING if there is already data in output queue */
	if (sox->flags & GS_SOX_WANT_WRITE)
	{
		DEBUGF("skip PING. WANT_WRITE already set.\n");
		return 0;
	}

	struct _gs_ping gping;
	memset(&gping, 0, sizeof gping);
	gping.type = GS_PKT_TYPE_PING; 

	ret = gs_write(sox, &gping, sizeof gping);
	if (ret == 0)
		sox->state = GS_STATE_PKT_PING;

	return 0;
}

static int
gs_pkt_listen_write(GS *gsocket, struct gs_sox *sox)
{
	int ret;

	DEBUGF("### PKT LISTEN write()\n");
	if (gsocket->flags & GS_FL_IS_CLIENT)
		ERREXIT("CC trying to send a listen message. Should send connect.\n");

	if (sox->flags & GS_SOX_WANT_WRITE)
		ERREXIT("pkt_listen_write() but WANT_WRITE already set\n");

	struct _gs_listen glisten;
	memset(&glisten, 0, sizeof glisten);
	glisten.type = GS_PKT_TYPE_LISTEN;
	glisten.version_major = GS_PKT_PROTO_VERSION_MAJOR;
	glisten.version_minor = GS_PKT_PROTO_VERSION_MINOR;

	memcpy(glisten.addr, gsocket->gs_addr.addr, MIN(sizeof glisten.addr, GS_ADDR_SIZE));

	ret = gs_write(sox, &glisten, sizeof glisten);
	if (ret == 0)
		sox->state = GS_STATE_PKT_LISTEN;

	return 0;
}

static int
gs_pkt_connect_write(GS *gsocket, struct gs_sox *sox)
{
	int ret;

	struct _gs_connect gconnect;
	memset(&gconnect, 0, sizeof gconnect);
	gconnect.type = GS_PKT_TYPE_CONNECT;
	gconnect.version_major = GS_PKT_PROTO_VERSION_MAJOR;
	gconnect.version_minor = GS_PKT_PROTO_VERSION_MINOR;
	gconnect.flags = gsocket->flags_proto;

	memcpy(gconnect.addr, gsocket->gs_addr.addr, MIN(sizeof gconnect.addr, GS_ADDR_SIZE));

	ret = gs_write(sox, &gconnect, sizeof gconnect);
	if (ret == 0)
		sox->state = GS_STATE_PKT_CONNECT;

	return 0;
}

static int
gs_pkt_accept_write(GS *gsocket, struct gs_sox *sox)
{
	int ret;

	struct _gs_accept gaccept;
	memset(&gaccept, 0, sizeof gaccept);
	gaccept.type = GS_PKT_TYPE_ACCEPT;

	ret = gs_write(sox, &gaccept, sizeof gaccept);
	if (ret == 0)
		sox->state = GS_STATE_PKT_ACCEPT; /* STOP HERE: implement resending of PKT_ACCEPT */

	return 0;
}

/*
 * Process a GS protocol message.
 */
static int
gs_pkt_dispatch(GS *gsocket, struct gs_sox *sox)
{
	if (sox->rbuf[0] == GS_PKT_TYPE_PONG)
	{
		DEBUGF("PONG received\n");
		return 0;
	}

	if (sox->rbuf[0] == GS_PKT_TYPE_START)
	{
		DEBUGF("START received.\n");
		sox->state = GS_STATE_APP_CONNECTED;
		gsocket->net.fd_accepted = sox->fd;

		gs_pkt_accept_write(gsocket, sox);
		return 0;
	}

	DEBUGF("Invalid Packet Type %d - Ignoring..\n", sox->rbuf[0]);

	return 0;
}

/*
 * Return length of bytes read or -1 on error (treat EOF as ECONNRESET & return -1)
 */
static ssize_t
gs_read(struct gs_sox *sox, size_t len)
{
	ssize_t ret;

	ret = read(sox->fd, sox->rbuf + sox->rlen, len);
	if (ret == 0)
		errno = ECONNRESET;
	if (ret <= 0)
		return -1;

	sox->rlen += ret;

	return ret;
}

/*
 * Socket has something to read() or write()
 * Return 0 on success.
 */
static int
gs_process_by_sox(GS *gsocket, struct gs_sox *sox)
{
	int ret;
	GS_CTX *gs_ctx = gsocket->ctx;

	if (FD_ISSET(sox->fd, gs_ctx->wfd))
	{
		if (sox->state == GS_STATE_SYS_CONNECT)
		{
			ret = gs_net_connect_by_sox(gsocket, sox);
			if (ret != 0)
				return -1;	/* ECONNREFUSED or other */

			DEBUGF("GS-NET Connection (TCP) ESTABLISHED (fd = %d)\n", sox->fd);
			return 0;
		}

		if ((sox->state == GS_STATE_PKT_PING) || (sox->state == GS_STATE_PKT_LISTEN))
		{
			ret = write(sox->fd, sox->wbuf, sox->wlen);
			/* Fatal is a single write fails even if wfd was set */
			if (ret != sox->wlen)
				return -1;
			sox->flags &= ~GS_SOX_WANT_WRITE;
			sox->state = GS_STATE_SYS_NONE;

			return 0;
		}

		/* write() data still in output buffer */
		DEBUGF("Oops. WFD ready but not in SYS_CONNECT or PKT_PING? (fd = %d, state = %d)\n", sox->fd, sox->state);
		return -1;
	}

	/* Read GS message. */
	/* Read GS MSG header (first octet) */
	if (sox->rlen == 0)
	{
		ret = gs_read(sox, 1);
		if (ret != 1)
			return -1;
	}

	size_t len_pkt;
	if (sox->rbuf[0] == GS_PKT_TYPE_LISTEN)
		len_pkt = sizeof (struct _gs_listen);
	else
		len_pkt = sizeof (struct _gs_ping);

	if (sox->rlen >= len_pkt)
		ERREXIT("BOOM! rlen %zu pkg_len %zu\n", sox->rlen, len_pkt);
	
	size_t len_rem = len_pkt - sox->rlen;
	ret = gs_read(sox, len_rem);
	if (ret < 0)
		return -1;

	if (sox->rlen > len_pkt)
		ERREXIT("BOOM!!\n");

	if (sox->rlen < len_pkt)
		return 0;	/* Not enough data yet */

	gs_pkt_dispatch(gsocket, sox);
	sox->rlen = 0;

	return 0;
}

/*
 * Handle sockets/KeepAlive in the background (non-blocking).
 * Return 0 on success.
 */
static int
gs_process(GS *gsocket)
{
	int ret;
	int i;

	gettimeofday(&gsocket->ctx->tv_now, NULL);

	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox *sox = &gsocket->net.sox[i];
		/* No PING/PONG (KeepAlive) and no further processing of any
		 * GS Protocol messages once the GS-SOCKET is connected.
		 * Instead forward all read() data to application via GS_read().
		 */
		if (sox->state == GS_STATE_APP_CONNECTED)
			continue;

		if (sox->state == GS_STATE_SYS_NONE)
		{
			/* Send a PING (KeepAlive) message */
			uint64_t tv_diff = GS_TV_DIFF(sox->tv_last_data, gsocket->ctx->tv_now);
			if (tv_diff > GS_SEC_TO_USEC(GS_DEFAULT_PING_INTERVAL))
			{
				DEBUGF("KeepAlive needs to be send here.\n");
				gs_pkt_ping_write(gsocket, sox);
				memcpy(&sox->tv_last_data, &gsocket->ctx->tv_now, sizeof sox->tv_last_data);
			}
		}

		if (FD_ISSET(sox->fd, gsocket->ctx->rfd) || FD_ISSET(sox->fd, gsocket->ctx->wfd))
		{
			ret = gs_process_by_sox(gsocket, sox);
			if (ret != 0)
				return -1;

			memcpy(&sox->tv_last_data, &gsocket->ctx->tv_now, sizeof sox->tv_last_data);
			/* Immediatly let app know that a new gs-connection has been accepted */
			if (gsocket->net.fd_accepted >= 0)
				break;
		}

	}

	return 0;
}


void
GS_fd_set(GS *gsocket)
{
	int i;
	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox *sox = &gsocket->net.sox[i];

		if (sox->flags & GS_SOX_WANT_WRITE)
		{
			DEBUGF("fd %d WANT-WRITE\n", sox->fd);
			FD_SET(sox->fd, gsocket->ctx->wfd);
		} else {
			FD_SET(sox->fd, gsocket->ctx->rfd);		/* read() if there is nothing to write() */
		}
	}
}

/*
 * Return 0 on success.
 * Called from gs_net_connect
 */
static int
gs_net_new_socket(GS *gsocket, struct gs_sox *sox)
{
	int s;
	int ret;

	gsocket->flags |= GS_FL_CALLED_NET_NEW_SOCKET;

	s = socket(PF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return -1;

	ret = fcntl(s, F_SETFL, O_NONBLOCK | fcntl(s, F_GETFL, 0));
	if (ret != 0)
		return -1;

	gsocket->ctx->max_sox = MAX(s, gsocket->ctx->max_sox);
	sox->fd = s;

	DEBUGF("socket(): %d\n", s);

	return 0;
}

/*
 * Connect to the GS-NET (non-blocking). 
 * Return 0 on success.
 * Return -1 on fatal error (must exist).
 */
static int
gs_net_connect(GS *gsocket)
{
	int ret;
	int i;
	GS_CTX *gs_ctx;

	if (gsocket == NULL)
		return -1;

	gs_ctx = gsocket->ctx;

	if (gs_ctx == NULL)
		return -1;


	if (gsocket->flags & GS_FL_TCP_CONNECTED)
		return 0;	/* Already connected */

	DEBUGF("gs_net_connect called\n");
	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox *sox = &gsocket->net.sox[i];
		// DEBUGF("fd %d\n", sox->fd);

		if (sox->fd >= 0)
			continue;	// Skip existing (valid) TCP sockets

		/* HERE: socket() does not exist yet. Create it. */
		ret = gs_net_new_socket(gsocket, sox);
		if (ret != 0)
			return -1;

		/* Connect TCP */
		ret = gs_net_connect_by_sox(gsocket, sox);
		DEBUGF("gs_net_connect_by_sox(): %d\n", ret);
		if (ret == -2)
			return -1;
	}	/* FOR loop over all sockets */

	return 0;
}

static void
gs_net_init(GS *gsocket, int backlog)
{
	int i;

	backlog = MIN(backlog, GS_MAX_SOX_BACKLOG);
	gsocket->net.n_sox = backlog;
	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox *sox = &gsocket->net.sox[i];
		sox->fd = -1;
	}
}

/*
 * Free fd from GS-NET structure and pass to application layer.
 */
int
gs_net_disengage_tcp_fd(GS *gsocket)
{
	int i;
	int new_fd = -1;

	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox * sox = &gsocket->net.sox[i];

		if (sox->fd != gsocket->net.fd_accepted)
			continue;
		
		/*
		 * Return GS-connected socket fd to app (and stop processing any PKT on that fd...).
		 */
		new_fd = gsocket->net.fd_accepted;
		gsocket->net.fd_accepted = -1;
		sox->state = GS_STATE_SYS_NONE;
		gsocket->flags &= ~GS_FL_TCP_CONNECTED;
		gsocket->net.conn_count -= 1;
		if (gsocket->net.conn_count < 0)
			ERREXIT("FATAL: conn_count dropped to %d\n", gsocket->net.conn_count);
		sox->fd = -1;

		return new_fd;
	}

	return -1;
}

/*
 * non-blocking.
 * Return -1 for waiting.
 * Return -2 on error
 * Return fd (0..MAX_FD) on success (tcp_fd)
 */
static int
gs_connect(GS *gsocket)
{
	int ret;
	int tcp_fd;

	/* Connect to GS-NET if not already connected */
	if (!(gsocket->flags & GS_FL_CALLED_NET_CONNECT))
	{
		gsocket->flags |= GS_FL_CALLED_NET_CONNECT;
		gsocket->flags |= GS_FL_IS_CLIENT;
		gs_net_init(gsocket, 1);
		ret = gs_net_connect(gsocket);
		if (ret != 0)
			return -2;

		return -1;
	}

	ret = gs_process(gsocket);
	DEBUGF("gs_process() = %d\n", ret);
	if (ret != 0)
		return -2;

	if (gsocket->net.fd_accepted >= 0)
	{
		DEBUGF("New GS connection SUCCESS (fd = %d)\n", gsocket->net.fd_accepted);
		tcp_fd = gs_net_disengage_tcp_fd(gsocket);

		return tcp_fd;
	}

	return -1; /* Waiting */
}

/*
 * Block until a GS connection has been achieved (via a GS-address)
 * Return -2 on error (fatal, must exit)
 * Return fd (0..MAX_FD) on success
 */
static int
gs_connect_blocking(GS *gsocket)
{
	int ret;

	gs_connect(gsocket);
	while (1)
	{

		struct timeval tv = {1, 0};
		FD_ZERO(gsocket->ctx->rfd);
		FD_ZERO(gsocket->ctx->wfd);
		GS_fd_set(gsocket);
		select(gsocket->ctx->max_sox + 1, gsocket->ctx->rfd, gsocket->ctx->wfd, NULL, &tv);

		ret = gs_connect(gsocket);
		if (ret == -2)
			return -2;
		if (ret >= 0)
		{
			/* Make tcp fd 'blocking' for caller. */
			fcntl(ret, F_SETFL, ~O_NONBLOCK & fcntl(ret, F_GETFL, 0));
			return ret;
		}
	}

	ERREXIT("Oops. This should not happen\n");
	return -2;
}

/*
 * Return fd (0..MAX_FD) on success.
 * Return -1 if still waiting for connection to be established.
 * Return -2 on error.
 */
int
GS_connect(GS *gsocket)
{
	int ret;

	if (gsocket->net.fd_accepted >= 0)
	{
		/* This GS-socket is already connected.... */
		errno = EBUSY;
		return -2;
	}

	if (gsocket->flags & GS_FL_NONBLOCKING)
		ret = gs_connect(gsocket);
	else
		ret = gs_connect_blocking(gsocket);

	return ret;
}

int
GS_listen(GS *gsocket, int backlog)
{
	gs_net_init(gsocket, backlog);
	gs_net_connect(gsocket);

	return 0;
}

/*
 * Return fd (0..MAX_FD) on success.
 * Return -1 if still waiting for new gs-connection.
 * Return -2 on error.
 */
static int
gs_accept(GS *gsocket)
{
	int ret;
	int tcp_fd;

	//DEBUGF("Called GS_accept()\n");
	ret = gs_process(gsocket);
	if (ret != 0)
		return -2;	/* ERROR */

	/* Check if there is a new gs-connection waiting */
	if (gsocket->net.fd_accepted >= 0)
	{
		DEBUGF("New GS Connection accepted (fd = %d)\n", gsocket->net.fd_accepted);

		tcp_fd = gs_net_disengage_tcp_fd(gsocket);
		#if 0
		for (i = 0; i < gsocket->net.n_sox; i++)
		{
			struct gs_sox * sox = &gsocket->net.sox[i];

			if (sox->fd != gsocket->net.fd_accepted)
				continue;
			
			/* Create a new TCP connection to GS-NET and wait for more incoming GS-connections.
			 * Return GS-connected socket fd to app (and stop processing any PKT on that fd...).
			 */
			int new_fd = gsocket->net.fd_accepted;
			gsocket->net.fd_accepted = -1;
			sox->state = GS_STATE_SYS_NONE;
			gsocket->flags &= ~GS_FL_TCP_CONNECTED;
			gsocket->net.conn_count -= 1;
			if (gsocket->net.conn_count < 0)
				ERREXIT("FATAL: conn_count dropped to %d\n", gsocket->net.conn_count);
			sox->fd = -1;
			gs_net_connect(gsocket);

			return new_fd;
		}
		#endif

		if (tcp_fd < 0)
			ERREXIT("Oops. New gs-connection but now in array? (fd_accepted = %d)\n", tcp_fd);

		gs_net_connect(gsocket);
		return tcp_fd;
	}

	return -1; /* Waiting for socket */
}

static int
gs_accept_blocking(GS *gsocket)
{
	int ret;

	while (1)
	{
		struct timeval tv = {1, 0};
		FD_ZERO(gsocket->ctx->rfd);
		FD_ZERO(gsocket->ctx->wfd);
		GS_fd_set(gsocket);
		select(gsocket->ctx->max_sox + 1, gsocket->ctx->rfd, gsocket->ctx->wfd, NULL, &tv);

		ret = gs_accept(gsocket);
		if (ret == -2)
			return -2;
		if (ret >= 0)
		{
			/* Make tcp fd 'blocking' for caller. */
			fcntl(ret, F_SETFL, ~O_NONBLOCK & fcntl(ret, F_GETFL, 0));
			return ret;
		}
	}

	ERREXIT("Oops. This should not happen\n");
	return -2;
}

int
GS_accept(GS *gsocket)
{
	int ret;

	if (gsocket->flags & GS_FL_NONBLOCKING)
		ret = gs_accept(gsocket);
	else
		ret = gs_accept_blocking(gsocket);

	return ret;
}

int
GS_close(GS *gsocket)
{
	if (gsocket == NULL)
		return 0;

	int i;
	/* Close all TCP connections to GS-Network */
	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox * sox = &gsocket->net.sox[i];
		if (sox->fd < 0)
			continue;
		close(sox->fd);
		sox->fd = -1;
	}

	free(gsocket);
	return 0;
}

/*
 * Return string of latest GS_* error
 * Format: ERROR-STR or erno-STR + ERROR-STR
 */


const char *
GS_CTX_strerror(GS_CTX *gs_ctx)
{
	char *dst = gs_ctx->err_buf2;
	int dlen = sizeof gs_ctx->err_buf2;

	if (errno != 0)
		snprintf(dst, dlen, "%s", strerror(errno));

	if (strlen(gs_ctx->err_buf) > 0)
	{
		if (errno != 0)
			strlcat(dst, " - ", dlen);
		snprintf(dst + strlen(dst), dlen - strlen(dst), "%s", gs_ctx->err_buf);
	}

	return gs_ctx->err_buf2;
}

int
GS_setsockopt(GS *gsocket, int level, const void *opt_value, size_t opt_len)
{
	if (gsocket->flags & GS_FL_CALLED_NET_NEW_SOCKET)
	{
		DEBUGF("ERROR: Cant set socket option after socket was created\n");
		errno = EPERM;		/* Cant set socket options after socket was created */
		return -1;
	}

	if (level == GS_OPT_SOCKWAIT)
		gsocket->flags_proto |= GS_FL_PROTO_WAIT;
	else if (level == GS_OPT_BLOCK)
		gsocket->flags &= ~GS_FL_NONBLOCKING;
	else
		return -1;

	return 0;
}

/******************************************************************************
 * GS UTILS                                                                   *
 ******************************************************************************/

static const char       b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t b58digits_map[] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};


bool
b58tobin(void *bin, size_t *binszp, const char *b58, size_t b58sz)
{

	size_t binsz = *binszp;
	const unsigned char *b58u = (void*)b58;
	unsigned char *binu = bin;
	size_t outisz = (binsz + 3) / 4;
	uint32_t outi[outisz];
	uint64_t t;
	uint32_t c;
	size_t i, j;
	uint8_t bytesleft = binsz % 4;
	uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
	unsigned zerocount = 0;
	
	if (!b58sz)
		b58sz = strlen(b58);
	
	memset(outi, 0, outisz * sizeof(*outi));
	
	// Leading zeros, just count
	for (i = 0; i < b58sz && b58u[i] == '1'; ++i)
		++zerocount;
	
	for ( ; i < b58sz; ++i)
	{
		if (b58u[i] & 0x80)
			// High-bit set on invalid digit
			return false;
		if (b58digits_map[b58u[i]] == -1)
			// Invalid base58 digit
			return false;
		c = (unsigned)b58digits_map[b58u[i]];
		for (j = outisz; j--; )
		{
			t = ((uint64_t)outi[j]) * 58 + c;
			c = (t & 0x3f00000000) >> 32;
			outi[j] = t & 0xffffffff;
		}
		if (c)
			// Output number too big (carry to the next int32)
			return false;
		if (outi[0] & zeromask)
			// Output number too big (last int32 filled too far)
			return false;
	}
	
	j = 0;
	switch (bytesleft) {
		case 3:
			*(binu++) = (outi[0] &   0xff0000) >> 16;
		case 2:
			*(binu++) = (outi[0] &     0xff00) >>  8;
		case 1:
			*(binu++) = (outi[0] &       0xff);
			++j;
		default:
			break;
	}
	
	for (; j < outisz; ++j)
	{
		*(binu++) = (outi[j] >> 0x18) & 0xff;
		*(binu++) = (outi[j] >> 0x10) & 0xff;
		*(binu++) = (outi[j] >>    8) & 0xff;
		*(binu++) = (outi[j] >>    0) & 0xff;
	}
	
	// Count canonical base58 byte count
	binu = bin;
	for (i = 0; i < binsz; ++i)
	{
		if (binu[i])
			break;
		--*binszp;
	}
	*binszp += zerocount;
	
	return true;	
}

#if 0
/* Convert Base58 address to binary. Check CRC.
 */
static int
b58dec(void *dst, char *str)
{
	return 0;
}
#endif

/* Convert 128 bit binary into base58 + CRC
 */
static int
b58enc(char *b58, size_t *b58sz, uint8_t *src, size_t binsz)
{
    const uint8_t *bin = src;
    int carry;
    size_t i, j, high, zcount = 0;
    size_t size;

    /* Find out the length. Count leading 0's. */
    while (zcount < binsz && !bin[zcount])
            ++zcount;

    size = (binsz - zcount) * 138 / 100 + 1;
    uint8_t buf[size];
    memset(buf, 0, size);

    for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
    {
            for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
            {
                    carry += 256 * buf[j];
                    buf[j] = carry % 58;
                    carry /= 58;
                    if (!j)
                    {
                            break;
                    }
            }
    }

    for (j = 0; j < size && !buf[j]; ++j);

    if (*b58sz <= zcount + size - j)
    {
            ERREXIT("Wrong size...%zu\n", zcount + size - j + 1);
            *b58sz = zcount + size - j + 1;
            return -1;
    }
    if (zcount)
    	memset(b58, '1', zcount);

    for (i = zcount; j < size; ++i, ++j)
    {
            b58[i] = b58digits_ordered[buf[j]];
    }
    b58[i] = '\0';
    *b58sz = i + 1;

	return 0;
}


/*
 * Convert a binary to a GS address.
 */
GS_ADDR *
GS_ADDR_bin2addr(GS_ADDR *addr, const void *data, size_t len)
{
	unsigned char md[SHA256_DIGEST_LENGTH];
	char b58[GS_ADDR_B58_LEN + 1];
	size_t b58sz = sizeof b58;

	memset(addr, 0, sizeof *addr);
	SHA256(data, len, md);
	memcpy(addr->addr, md, sizeof addr->addr);
	HEXDUMP(addr->addr, sizeof addr->addr);

	b58enc(b58, &b58sz, md, GS_ADDR_SIZE);
	DEBUGF("b58 (%lu): %s\n", b58sz, b58);
	addr->b58sz = b58sz;
	strncpy(addr->b58str, b58, sizeof addr->b58str - 1);

	return addr;
}
/*
 * Convert a human readable string (password) to GS address. 
 */
GS_ADDR *
GS_ADDR_str2addr(GS_ADDR *addr, char *str)
{
	addr = GS_ADDR_bin2addr(addr, str, strlen(str));

	return addr;
}

/*
 * Derive a GS-Address from IPv4 + Port tuple.
 * Use at your own risk. GS-Address can easily be guessed.
 */
GS_ADDR *
GS_ADDR_ipport2addr(GS_ADDR *addr, uint32_t ip, uint16_t port)
{
	struct in_addr in;
	char buf[128];

	in.s_addr = ip;

	snprintf(buf, sizeof buf, "%s:%d", inet_ntoa(in), ntohs(port));
	//DEBUGF("%s\n", buf);
	GS_ADDR_str2addr(addr, buf);
	
	return addr;
}


