
#ifndef __GST_PKT_H__
#define __GST_PKT_H__ 1


#define GST_PKT_BUF_SIZE		(1024)	/* For protocol control messages */
#define GST_MAX_FILENAME_LEN	(255)

#define GST_VERSION_MAJOR		(1)
#define GST_VERSION_MINOR		(0)

typedef struct _pkt_ctx
{
	size_t len_needed;		/* Number of bytes needed */
	size_t len;				/* Number of bytes available */
	uint8_t buf[GST_PKT_BUF_SIZE];
} PKT_CTX;

/*
 * C2S
 * First packet send from CLIENT to SERVER.
 */
struct _pkt_helo
{
	uint8_t type;		/* GST_PKT_TYPE_HELO */
	uint8_t version_major:4;
	uint8_t version_minor:4;
	uint8_t flags;
	uint8_t reserved;
};

/*
 * C2S
 * Offer filename.
 */
struct _pkt_offer
{
	uint8_t type;		/* GST_PKT_TYPE_OFFER */
	uint8_t flags;
	uint8_t reserved[2];

	uint8_t filename[GST_MAX_FILENAME_LEN + 1];
};

#define GST_PKT_FL_PIPE		(0x01)		/* like /dev/stdin or even /dev/urandom */
//#define GST_PKT_FL_END		(0x02)		/* End of transmission (all files) */

/*
 * S2C
 * Request start of transmission from offset.
 */
struct _pkt_accept
{
	uint8_t type;			/* GST_PKT_TYPE_ACCEPT */
	uint8_t reserved[7];

	uint64_t file_offset;	/* 0 == Client to start from beginning */
};

/*
 * C2S
 * Transmit data to server for last requested file.
 */
struct _pkt_data
{
	uint8_t type;			/* GST_PKT_TYPE_DATA */
	uint8_t reserved[7];

	uint64_t data_length;	/* 0xFFFF...FF means Unknown file length */
	uint8_t data[0];
};

#define GST_PKT_TYPE_HELO		(0x01)
#define GST_PKT_TYPE_OFFER		(0x02)
#define GST_PKT_TYPE_ACCEPT		(0x03)
#define GST_PKT_TYPE_DATA		(0x04)

int PKT_CTX_init(PKT_CTX *ctx);
int PKT_CTX_free(PKT_CTX *ctx);
int pkt_build_helo(PKT_CTX *ctx);
int pkt_build_offer(PKT_CTX *ctx, char *filename);
int pkt_build_accept(PKT_CTX *ctx, uint64_t len);
int pkt_build_data(PKT_CTX *ctx, uint64_t len);

int SSL_PKT_read(SSL *ssl, PKT_CTX *pkt, int type);
int SSL_PKT_write(SSL *ssl, PKT_CTX *pkt);

#endif /* !__GST_PKT_H__ */
