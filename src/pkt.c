
#include "common.h"
#include "pkt.h"

int
PKT_CTX_init(PKT_CTX *ctx)
{
	memset(ctx, 0, sizeof *ctx);

	ctx->len_needed = 1;

	return 0;
}

int
PKT_CTX_free(PKT_CTX *ctx)
{
	/* Nothing to be done here for now */
	return 0;
}


/*****************************
 * PACKET BUILDING FUNCTIONS *
 *****************************/
int
pkt_build_helo(PKT_CTX *ctx)
{
	struct _pkt_helo *helo = (struct _pkt_helo *)ctx->buf;

	memset(helo, 0, sizeof *helo);

	helo->type = GST_PKT_TYPE_HELO;
	helo->version_major = 1;
	helo->version_minor = 0;
	ctx->len = sizeof *helo;

	return 0;
}

/*
 * filename = "" -> PIPE
 */
int
pkt_build_offer(PKT_CTX *ctx, char *filename)
{
	struct _pkt_offer *offer = (struct _pkt_offer *)ctx->buf;

	memset(offer, 0, sizeof *offer);
	offer->type = GST_PKT_TYPE_OFFER;
	if (filename != NULL)
	{
		if (strlen(filename) <= 0)
			offer->flags = GST_PKT_FL_PIPE;
		else
			memcpy(offer->filename, filename, MIN(sizeof offer->filename, strlen(filename)));
	} //else {
		// offer->flags = GST_PKT_FL_END;
	// }
	ctx->len = sizeof *offer;

	return 0;
}

int
pkt_build_accept(PKT_CTX *ctx, uint64_t len)
{
	struct _pkt_accept *acc = (struct _pkt_accept *)ctx->buf;

	memset(acc, 0, sizeof *acc);
	acc->type = GST_PKT_TYPE_ACCEPT;
	acc->file_offset = htonll(len);
	ctx->len = sizeof *acc;

	return 0;
}

int
pkt_build_data(PKT_CTX *ctx, uint64_t len)
{
	struct _pkt_data *data = (struct _pkt_data *)ctx->buf;

	memset(data, 0, sizeof *data);
	data->type = GST_PKT_TYPE_DATA;
	data->data_length = htonll(len);	/* Number of bytes to follow */
	ctx->len = sizeof *data;

	return 0;
}

/*
 * Return number of bytes read on success.
 * Return -1 on error;
 */
int
SSL_PKT_read(SSL *ssl, PKT_CTX *pkt, int type)
{
	int num;

	switch (type)
	{
		case GST_PKT_TYPE_HELO:
			pkt->len_needed = sizeof (struct _pkt_helo);
			break;
		case GST_PKT_TYPE_ACCEPT:
			pkt->len_needed = sizeof (struct _pkt_accept);
			break;
		case GST_PKT_TYPE_DATA:
			pkt->len_needed = sizeof (struct _pkt_data);
			break;
		case GST_PKT_TYPE_OFFER:
			pkt->len_needed = sizeof (struct _pkt_offer);
			break;
		default:
			DEBUGF("type %d not supported\n", type);
			return -1;
	}

	pkt->len = 0;
	while (1)
	{
		num = SSL_read(ssl, pkt->buf + pkt->len, pkt->len_needed);
		if (num <= 0)
		{
			DEBUGF("SSL_read() = %d\n", num);
			return -1;
		}

		pkt->len += num;
		pkt->len_needed -= num;

		if (pkt->len_needed <= 0)
			break;
	}

	if (pkt->buf[0] != type)
	{
		DEBUGF("Woops. Type == %d received, exepcted %d\n", pkt->buf[0], type);
		return -1;		/* Protocol error. We expected a different package */
	}

	pkt->len_needed = 1;

	return pkt->len;
}

/*
 * Write packet and block until it's fully written.
 */
int
SSL_PKT_write(SSL *ssl, PKT_CTX *pkt)
{
	int num;

	XASSERT(pkt->len > 0, "pkt->len is to small: %zu\n", pkt->len);
	num = SSL_write(ssl, pkt->buf, pkt->len);
	if (num != pkt->len)
	{
		DEBUGF("SSL write %zu != %d\n", pkt->len, num);
		return -1;
	}

	pkt->len = 0;
	pkt->len_needed = 1;

	return num;
}

