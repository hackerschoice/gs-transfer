
#ifndef __LIBGSOCKET_H__
#define __LIBGSOCKET_H__ 1

#ifndef GS_MAX
# define GS_MAX(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

#ifndef GS_MIN
# define GS_MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#define GS_ADDR_SIZE				(16)	/* 128 bit */
#define GS_ADDR_B58_LEN 			(GS_ADDR_SIZE) * 138 / 100 + 1
#define GS_ADDR_PROTO_SIZE			(32)	/* 256 bit */
#define GS_MAX_SOX_BACKLOG			(5)		/* Relevant for GS_listen() only */

#define GS_TV_DIFF(tv_a, tv_b)	(((uint64_t)tv_b.tv_sec * 1000000 + tv_b.tv_usec) - ((uint64_t)tv_a.tv_sec * 1000000 + tv_a.tv_usec))
#define GS_SEC_TO_USEC(sec)		(sec * 1000000)



/* ###########################
 * ### PROTOCOL DEFINITION ###
 * ###########################
 */
/* First message from Listening Client (LC) to GS-Network (GN) [server]
 * LC2GN: Register a GS-Address for listening.
 */
struct _gs_listen		/* 128 bytes */
{
	uint8_t type;
	uint8_t version_major;
	uint8_t version_minor;
	uint8_t flags;

	uint8_t reserved2[28];

	uint8_t addr[GS_ADDR_PROTO_SIZE];		/* 32 bytes */
	uint8_t reserved3[64];
};

/*
 * First message from Connecting Client (CC) to GS-Network (GN) [server]
 * CC2GN: Connect a listening GS-Address.
 * CC awaiting _gs_start from GN.
 */
struct _gs_connect
{
	uint8_t type;
	uint8_t version_major;
	uint8_t version_minor;
	uint8_t flags;

	uint8_t reserved2[28];

	uint8_t addr[GS_ADDR_PROTO_SIZE];		/* 32 bytes */
	uint8_t reserved3[64];
};
#define GS_PKT_PROTO_VERSION_MAJOR		(0x01)
#define GS_PKT_PROTO_VERSION_MINOR		(0x02)

#define GS_FL_PROTO_WAIT				(0x01)	/* Wait for LC to connect */

//#define GS_PKT_PROTO_FL_CLIENT			(0x01)

/*
 * all2GN
 */
struct _gs_ping
{
	uint8_t type;
	uint8_t reserved[3];

	uint8_t payload[28];
};

/*
 * GN2all
 */
struct _gs_pong
{
	uint8_t type;
	uint8_t reserved[3];

	uint8_t payload[28];
};

/* GN2all: New incoming connection.
 * GN must not send any further GS messages.
 */
struct _gs_start
{
	uint8_t type;
	uint8_t reserved[3];

	uint8_t reserved2[28];
};

/*
 * all2GN: Accepting incoming connection.
 * LC/CC must not send any further GS messages.
 */
struct _gs_accept
{
	uint8_t type;
	uint8_t reserved[3];

	uint8_t reserved2[28];
};

#define GS_PKT_TYPE_LISTEN	(0x01)	/* LC2GN */
#define GS_PKT_TYPE_CONNECT	(0x02)	/* CC2GN */
#define GS_PKT_TYPE_PING	(0x03)	/* all2GN */
#define GS_PKT_TYPE_PONG	(0x04)  /* GN2all */
#define GS_PKT_TYPE_START	(0x05)	/* GN2all */
#define GS_PKT_TYPE_ACCEPT	(0x06)	/* all2GN */


#define GS_MAX_MSG_LEN	GS_MAX(sizeof (struct _gs_listen), GS_MAX(sizeof (struct _gs_ping), GS_MAX(sizeof (struct _gs_pong), sizeof (struct _gs_start))))

/*
 * - GS-Network host/port
 * - Handle TCP sockets (non-blocking)
 */
typedef struct
{
	int max_sox;
	fd_set *rfd;
	fd_set *wfd;
	struct timeval tv_now;
	int flags;
	char err_buf[256];
	char err_buf2[256];
} GS_CTX;

#define GS_CTX_FL_RFD_INTERNAL		(0x01)	/* Use internal FD_SET */

/* TCP network address may depend on GS_ADDR (load balancing) */
struct gs_sox
{
	int fd;
	int state;
	int flags;
	uint8_t rbuf[GS_MAX_MSG_LEN];
	size_t rlen;
	uint8_t wbuf[GS_MAX_MSG_LEN];
	size_t wlen;
	struct timeval tv_last_data;		/* For KeepAlive */
};

#define GS_STATE_SYS_NONE		(0)
#define GS_STATE_SYS_CONNECT	(1)		/* need call to 'connect()' _again_. */
#define GS_STATE_PKT_LISTEN		(2)
#define GS_STATE_PKT_PING		(3)		/* need call to pkt_ping_write() */
#define GS_STATE_APP_CONNECTED	(4)		/* Application is connected. Passingthrough of data (no pkt any longer) */
#define GS_STATE_PKT_CONNECT	(5)
#define GS_STATE_PKT_ACCEPT		(6)
#define GS_SOX_WANT_WRITE		(1)

struct gs_net
{
	uint16_t port;	/* NBO */
	uint32_t addr;	/* IPv4, NBO */
	int conn_count;
	struct gs_sox sox[GS_MAX_SOX_BACKLOG];
	int n_sox;				/* Number of sox[n] entries */
	int fd_accepted;
};


typedef struct
{
	uint8_t addr[GS_ADDR_SIZE];
	char b58str[GS_ADDR_B58_LEN + 1];		/* Base58 string representation of gs-address. 0-terminated. */
	size_t b58sz;							/* Base58 size */
} GS_ADDR;

/*
 * A specific GS connection with a single GSOCKET-ID.
 * There can be multiple connection per GSOCKET-ID (eventually).
 */
typedef struct
{
	GS_CTX *ctx;
	GS_ADDR gs_addr;
	uint32_t flags;
	uint32_t flags_proto;		/* Protocol Flags for pkt */
	struct gs_net net;
} GS;
#define GS_FL_TCP_CONNECTED			(0x01)		/* All TCP sockets are connected */
#define GS_FL_NONBLOCKING			(0x02)			/* Dont use NON-BLOCKING */
#define GS_FL_CALLED_NET_CONNECT	(0x04)	/* GS_connect() already called GS_FL_CALLED_NET_CONNECT */
#define GS_FL_IS_CLIENT				(0x08)
#define GS_FL_CALLED_NET_NEW_SOCKET	(0x10)

/* #####################################
 * ### GSOCKET FUNCTION DECLARATIONS ###
 * #####################################
 */

int GS_CTX_init(GS_CTX *, fd_set *rfd, fd_set *wfd);
int GS_CTX_free(GS_CTX *);
GS *GS_new(GS_CTX *ctx, GS_ADDR *addr);		/* Connect's to GS-Network? */
const char *GS_CTX_strerror(GS_CTX *gs_ctx);

void GS_fd_set(GS *gsocket);
int GS_connect(GS *gsocket);	/* Fail if no such GS-ID is listening */
int GS_listen(GS *gsocket, int backlog);	/* Listen for an incoming GS connection */
int GS_accept(GS *gsocket);	/* Wait until client connects by GS-ID and return Unix fileno */
int GS_close(GS *gsocket);		/* close() and free() a connected GS */
int GS_setsockopt(GS *gsocket, int level, const void *opt_value, size_t opt_len);
#define GS_OPT_SOCKWAIT		(0x03)
#define GS_OPT_BLOCK		(0x04)	/* Blocking TCP */
GS_ADDR *GS_ADDR_bin2addr(GS_ADDR *addr, const void *data, size_t len);
GS_ADDR *GS_ADDR_str2addr(GS_ADDR *addr, char *str);
GS_ADDR *GS_ADDR_ipport2addr(GS_ADDR *addr, uint32_t ip, uint16_t port);

#endif /* !__LIBGSOCKET_H__ */
