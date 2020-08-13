
#include "common.h"
#include <openssl/srp.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "gsocket.h"
#include "pkt.h"
#include "display.h"
#include "gs-utils.h"

struct _gopt gopt;	/* Global variables */

static SRP_VBASE *srpData;

static void usage(char *errstr);
static void kd_secret(GS_ADDR *addr, char *kd_path, char *secret);
static void do_user_secret(void);
static void init_vars_server(void);
static void init_vars_client(void);
static int server_recvfile(void);

static char *
strsslerr(int err)
{
	switch (err)
	{
		case SSL_ERROR_NONE:
			return "None";
		case SSL_ERROR_ZERO_RETURN:
			return "ZERO_RETURN";
		case SSL_ERROR_WANT_READ:
			return "WANT_READ";
		case SSL_ERROR_WANT_WRITE:
			return "WANT WRITE";
		case SSL_ERROR_SYSCALL:
			return "SYSCALL";
		case SSL_ERROR_SSL:
			return "FATAL ERROR";
	}
	return "unknown :/";
}

static void
SRP_server_init(SSL_CTX *ctx)
{
	SRP_gN *gN;
	SRP_user_pwd *p;

	srpData = SRP_VBASE_new(NULL);
	XASSERT(srpData != NULL, "\n");

	p = (SRP_user_pwd *)OPENSSL_malloc(sizeof (SRP_user_pwd));
	XASSERT(p != NULL, "\n");

	gN = SRP_get_default_gN(GST_DFL_STRENGTH);
	XASSERT(gN != NULL, "SRP_get_default_gN()");

	char *srpCheck = SRP_check_known_gN_param(gN->g, gN->N);
	XASSERT(srpCheck != NULL, "\n");

	BIGNUM *salt = NULL;
	BIGNUM *verifier = NULL;
	SRP_create_verifier_BN("user", gopt.srp_secret.b58str, &salt, &verifier, gN->N, gN->g);

	p->id = "user";
	p->g = gN->g;
	p->N = gN->N;
	p->s = salt;
	p->v = verifier;
	p->info = NULL;

	sk_SRP_user_pwd_push(srpData->users_pwd, p);

	//SRP_VBASE_free(srpData);
}

static int
SRP_CB_server(SSL *ssl, int *ad, void *arg)
{
	SRP_user_pwd *p;
	SRP_VBASE *lsrpData = (SRP_VBASE *)arg;

	if (lsrpData == NULL)
		return -1;	// Not ready yet.

	p = SRP_VBASE_get1_by_user(lsrpData, "user");
	if (p == NULL)
		return -1;	// Bad User

	if (SSL_set_srp_server_param(ssl, p->N, p->g, p->s, p->v, NULL) != 1)
		ERREXIT("SSL_set_srp_server_param() failed...\n");
	SRP_user_pwd_free(p);

	return SSL_ERROR_NONE;
}

char *
SRP_CB_client(SSL *ssl, void *arg)
{
	return OPENSSL_strdup(gopt.srp_secret.b58str);
}

static void
init_defaults(void)
{
	gopt.verboselevel = 1;
#ifdef DEBUG
	gopt.verboselevel = 255;
#endif
	signal(SIGPIPE, SIG_IGN);

	gopt.out = stdout;
}

/*
 * Called _after_ getopt
 */
static void
init_vars(void)
{
	int ret;

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	XASSERT(RAND_status() == 1, "RAND_status()");

	VOUT(2, "%s [0x%lxL]\n", OPENSSL_VERSION_TEXT, OPENSSL_VERSION_NUMBER);

	gopt.ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (gopt.ssl_ctx == NULL)
		ERREXIT("SSL_CTX_new()\n");

	long options = 0;
	options |= SSL_OP_NO_SSLv2;
	options |= SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
	options |= SSL_OP_NO_TICKET;
	options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
	options |= SSL_OP_SINGLE_DH_USE; 
	SSL_CTX_set_options(gopt.ssl_ctx, options);

	ret = SSL_CTX_set_cipher_list(gopt.ssl_ctx, GST_DFL_CIPHER);
	if (ret != 1)
		ERREXIT("Failed to set cipher\n");

	long mode;
	mode = SSL_CTX_get_mode(gopt.ssl_ctx);
	mode |= SSL_MODE_AUTO_RETRY;	/* Let OpenSSL handle all writes internally */
	SSL_CTX_set_mode(gopt.ssl_ctx, mode);

	/* Ask for secret or read from file */
	do_user_secret();

	if (gopt.sec_str == NULL)
		usage("Must specify a secret\n");

	if (gopt.sec_str != NULL)
	{
		if (strlen(gopt.sec_str) < 16)
				usage("Secret to short. Min length of 16 characters\n");
	}

	/* Generate a SRP Secret from Secret */
	kd_secret(&gopt.srp_secret, "KD/1/2/THC/KeyForSRPSecret/Path", gopt.sec_str);
	VOUT(2, "SRP Secret: %s\n", gopt.srp_secret.b58str);

	/* Generate a GS address from Secret */
	kd_secret(&gopt.gs_addr, "KD/A/B/C/THC/KeyForAddress/Path", gopt.sec_str);

	ret = GS_CTX_init(&gopt.gs_ctx, NULL, NULL);

	XASSERT(ret == 0, "GS_CTX_init(): %d\n", ret);

	gopt.gsocket = GS_new(&gopt.gs_ctx, &gopt.gs_addr);
	XASSERT(gopt.gsocket != NULL, "GS_new(): %s\n", GS_CTX_strerror(&gopt.gs_ctx));

	/* Operate on BLOCKING sockets */
	GS_setsockopt(gopt.gsocket, GS_OPT_BLOCK, NULL, 0);

	/* Initialize SSL-SRP */
	if (gopt.flags & GST_FL_IS_SERVER)
	{
		init_vars_server();
	} else {

		init_vars_client();
	}
	/* Must happen _after_ init_vars_server/client(). */
	gopt.ssl = SSL_new(gopt.ssl_ctx);
	XASSERT(gopt.ssl != NULL, "\n");

}


static void
init_vars_server(void)
{
	SRP_server_init(gopt.ssl_ctx);
	SSL_CTX_set_srp_username_callback(gopt.ssl_ctx, SRP_CB_server);
	if (SSL_CTX_set_srp_cb_arg(gopt.ssl_ctx, srpData) != 1)
		ERREXIT("SSL_CTX_set_srp_cb_arg() failed...\n");

}

static void
init_vars_client(void)
{

	SSL_CTX_set_srp_username(gopt.ssl_ctx, "user");
	SSL_CTX_set_srp_cb_arg(gopt.ssl_ctx, "user");
	SSL_CTX_set_srp_client_pwd_callback(gopt.ssl_ctx, SRP_CB_client);
}

static void
usage(char *errstr)
{
	fprintf(stderr, ""
"Version %s\n"
" gs-transfer [-O] [-d nnn] [-s secret] [-k file] <FILE> <FILE> ...\n"
"\n"
/*" -l           Persistant Server Mode (does not exit yet)\n" */
" -d nnn       Debug Level Output [default: 1]\n"
" -s <secret>  Shared Secret (e.g. password).\n"
" -k <file>    Read Secret from file.\n"
" -O           Output to standard output [Server only]\n"
"\n"
"Example Server Side                 # Example Client Side:\n"
"   $ ./gs-transfer                  # $ ./gs-transfer *.tar.gz *.mp3\n"
"\n"
"Example Server Side                 # Example Client Side:\n"
"   $ ./gs-transfer -O | tar xfz -   # $ tar cfz - *.c | ./gs-transfer -s <sec> -\n"
"\n"
"", VERSION);

	if (errstr != NULL)
	{
		fprintf(stderr, "\nERROR: %s", errstr);
	}

	exit(255);
}

/*
 * Return 0 on success.
 */
static int
user_secret_from_file(const char *file)
{
	FILE *fp;
	char buf[256];
	int ret;

	if (file == NULL)
		return -1;

	memset(buf, 0, sizeof buf);
	fp = fopen(file, "r");
	if (fp == NULL)
		return -1;

	ret = fread(buf, 1, sizeof buf - 1, fp);
	fclose(fp);

	if (ret < 0)
		return -1;

	gopt.sec_str = strdup(buf);
	return 0;

}

static int
user_secret_from_stdin(void)
{
	size_t n = 0;
	char *ptr = NULL;
	ssize_t len;

	while (1)
	{
		fprintf(gopt.out, "Enter Secret (or press Enter to generate): ");
		fflush(gopt.out);
		len = getline(&ptr, &n, stdin);
		XASSERT(len > 0, "getline()\n");
		if (ptr[len - 1] == '\n')
			ptr[len - 1] = 0;	// Remove '\n' 
		if (strlen(ptr) == 0)
			return -1;
		if (strlen(ptr) >= 16)
			break;
		fprintf(gopt.out, "Too short. Minimum length of 16 characters.\n");
		fflush(gopt.out);
	}

	gopt.sec_str = strdup(ptr);

	return 0;
}

static void
do_user_secret(void)
{
	int ret;

	ret = user_secret_from_file(gopt.sec_file);

	if (gopt.sec_str != NULL)
	{
		if (strlen(gopt.sec_str) >= 16)
			return;

		fprintf(stderr, "Secret is too short. Minimum lengh of 16 characters.\n");
		exit(255);	/* FATAL */
	}

	/* HERE: File not found or read error */
	/* Try to read it from stdin */
	ret = user_secret_from_stdin();
	if (ret == 0)
		return;

	/* Generate new secret */
	uint8_t buf[GST_SECRET_MAX_LEN + 1];
	ret = RAND_bytes(buf, GST_SECRET_MAX_LEN);
	XASSERT(ret == 1, "RAND_bytes() failed.\n");

	GS_ADDR addr;
	GS_ADDR_bin2addr(&addr, buf, GST_SECRET_MAX_LEN);
	gopt.sec_str = strdup(addr.b58str);
	fprintf(gopt.out, "=Secret: \"%s\"\n", gopt.sec_str);
	fflush(gopt.out);

}


static void
do_getopt(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "Os:k:d:hl")) != -1)
	{
		switch (c)
		{
			case 'O':
				gopt.flags |= GST_FL_STDOUT;
				break;
			case 's':
				gopt.sec_str = optarg;
				break;
			case 'k':
				gopt.sec_file = optarg;
				break;
			case 'd':
				gopt.verboselevel = atoi(optarg);
				break;
			case 'l':
				/* Accept multiple connections from different peers */
				gopt.flags |= GST_FL_IS_MULTI_SERVER;
				break;
			case 'h':
			default:
				usage(NULL);
				break;
		}
	}

	if (optind >= argc)
	{
		gopt.flags |= GST_FL_IS_SERVER;
	}

	if (gopt.flags & GST_FL_STDOUT)
	{
		gopt.out = stderr;
	}

	gopt.n_files = argc - optind;
	gopt.files = &argv[optind];
}

#if 0
static int
make_socket(uint16_t port)
{
	int sox;
	struct sockaddr_in addr;

	sox = socket(PF_INET, SOCK_STREAM, 0);
	setsockopt(sox, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof (int));
	XASSERT(sox >= 0, "\n");

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sox, (struct sockaddr *)&addr, sizeof (addr)) < 0)
		ERREXIT("bind() failed: %s\n", strerror(errno));

	return sox;
}
#endif

static void
do_server(void)
{
	int ret;
	int tcp_fd;

	DEBUGF("### SERVEiER ###\n");
	//init_vars_server();

	
#if 1
	GS_listen(gopt.gsocket, 1);
	VOUT(2, "=Global Socket %s.gsocket\n", gopt.gs_addr.b58str);
	VOUT(1, "=Waiting for Sender...");

	tcp_fd = GS_accept(gopt.gsocket);
	if (tcp_fd < 0)
		ERREXIT("GS_accept(): %s\n", GS_CTX_strerror(gopt.gsocket->ctx));
	GS_close(gopt.gsocket);
	VOUT(1, "Success!\n");
	VOUT(2, "=New Global Socket Connection\n");

#else
	int lsox;
	lsox = make_socket(31338);
	if (listen(lsox, 1) < 0)
		ERREXIT("listen(): %s\n", strerror(errno));

	int sox;
	struct sockaddr_in addr;
	socklen_t addrsz = sizeof (addr);

	DEBUGF("listening...\n");
	sox = accept(lsox, (struct sockaddr *)&addr, &addrsz);
	if (sox < 0)
		ERREXIT("accept(): %s\n", strerror(errno));
	DEBUGF("New connection\n");
	tcp_fd = sox;

#endif
	if (SSL_set_fd(gopt.ssl, tcp_fd) != 1)
	{
		ERR_print_errors_fp(stderr);
		ERREXIT("SSL_set_fd()\n");
	}
	ret = SSL_accept(gopt.ssl);
	DEBUGF("SSL_accept() = %d\n", ret);


	XASSERT(ret == 1, "SSL_accept()");
	char *user = SSL_get_srp_username(gopt.ssl);
	if (user == NULL)
		ERREXIT("Peer is not using SRP\n");
	VOUT(1, "=Encryption: %s (Prime: %s bits)\n", GST_DFL_CIPHER, GST_DFL_STRENGTH);

	DEBUGF("user = %s\n", user);

	PKT_CTX pkt;
	PKT_CTX_init(&pkt);
	SSL_PKT_read(gopt.ssl, &pkt, GST_PKT_TYPE_HELO);
	struct _pkt_helo *helo = (struct _pkt_helo *)pkt.buf;
	VOUT(2, "Protocol: %d.%d\n", helo->version_major, helo->version_minor);
	if (helo->version_major != GST_VERSION_MAJOR)
		ERREXIT("Protocol version mismatch. This Version %d.%d, Remote Version: %d.%d.\n", GST_VERSION_MAJOR, GST_VERSION_MINOR, helo->version_major, helo->version_minor);


	while (1)
	{
		ret = server_recvfile();
		if (ret != 0)
		{
			break;
		}
	}
	ret = SSL_shutdown(gopt.ssl);
	DEBUGF("SSL_shutdown() = %d\n", ret);
	if (ret != 1)
	{
		DEBUGF("Broken Pipe. Not all data was received\n");
	} else {
		/* Clean Shut Down. Display that last file was successfully received */
		DP_update(0, 0, 1);
	}

	exit(0);
}

const char fname_valid_char[] = ""
"................"
"................"
" !.#$%&.()*+,-.."	/* Dont allow " or / or ' */
"0123456789:;.=.."	/* Dont allow < or > or ? */
"@ABCDEFGHIJKLMNO"
"PQRSTUVWXYZ[.]^_"	/* Dont allow \ */
".abcdefghijklmno"	/* Dont allow ` */
"pqrstuvwxyz{.}.." 	/* Dont allow | or ~ */
"";
/*
 * Return 0 on success (next file).
 * Return 1 when finished. (no more files).
 * Return <0 on error.
 */
static int
server_recvfile(void)
{
	PKT_CTX pkt;
	FILE *fp;
	int ret;
	char fname[256];
	uint64_t offset = 0xFFFFFFFFFFFFFFFF;	/* REJECT */

	PKT_CTX_init(&pkt);

	ret = SSL_PKT_read(gopt.ssl, &pkt, GST_PKT_TYPE_OFFER);
	DEBUGF("SSL_PKT_read() = %d\n", ret);
	if (ret < 0)
		return -1;

	struct _pkt_offer *offer = (struct _pkt_offer *)pkt.buf;


	if (gopt.flags & GST_FL_STDOUT)
	{
		fp = stdout;
		offset = 0;
		snprintf(fname, sizeof fname, "<STDOUT>");
	} else {
		/* Sanitize filename...*/
		uint8_t *f = offer->filename;
		for (int i = 0; i < sizeof offer->filename; i++)
		{
			if (f[i] == 0)
				break;
			uint8_t c = f[i];
			if (c < sizeof fname_valid_char)
			{
				if (c == '.')
					continue;
				if (fname_valid_char[c] == c)
					continue;
			}

			f[i] = '#';	/* Everything we dont like we turn into X. hehe. */
		}

		snprintf(fname, sizeof fname, "%s", f);
		DEBUGF("Filename: '%s'\n", fname);

		/* See if file exists and is not a symbolic link */
		int is_ok_file = 0;
		struct stat res;
		uint64_t fz = 0;
		ret = lstat(fname, &res);
		DEBUGF("lstat() = %d, %s\n", ret, strerror(errno));
		if (ret != 0)
		{
			/* HERE: File/Symlink does not exit. Can create it */
			is_ok_file = 1;		/* File/Symlink does not exist. Can create it */
		} else {
			/* HERE: File/symlink exists */
			if (S_ISREG(res.st_mode))
			{
				is_ok_file = 1;
				fz = res.st_size;
			}
		}

		if (is_ok_file == 1)
		{
			/* HERE: Regular File. Not a symlink. Not a device */
			fp = fopen(fname, "a");
			if (fp != NULL)
			{
				offset = ftell(fp);
			}	
		}
	}

	DEBUGF("Accepting at offset %llx\n", offset);
	pkt_build_accept(&pkt, offset);
	ret = SSL_PKT_write(gopt.ssl, &pkt);
	if (offset == 0xFFFFFFFFFFFFFFFF)
	{
		fprintf(stderr, "%s - Rejected...\n", strlen(fname)?fname:"<STDOUT>");
		return 0;	/* NEXT FILE */
	}

	ret = SSL_PKT_read(gopt.ssl, &pkt, GST_PKT_TYPE_DATA);
	if (ret < 0)
		return -1;
	DEBUGF("data packet = %d\n", ret);
	struct _pkt_data *data = (struct _pkt_data *)pkt.buf;

	uint64_t len;
	len = ntohll(data->data_length);
	DEBUGF("Expecting %"PRIu64" bytes to follow\n", len);

	char buf[4096];
	int num;
	int max_read = sizeof buf;

	DP_init(fname, gopt.out);

	off_t cur_pos = offset;
	off_t fz = cur_pos + len;
	/* Sending peer does not know the full file size */
	DP_update(fz, cur_pos, 1);

	while (len > 0)
	{
		if (len < max_read)
			max_read = len;

		num = SSL_read(gopt.ssl, buf, max_read);
		if (num <= 0)
		{
			int err = SSL_get_error(gopt.ssl, num);

			DEBUGF("num = %d, len %llu, err = %d\n", num, len, err);
			/* Check if peer gracefully shut connection (end of file for PIPE transfer) */
			if (err != SSL_ERROR_ZERO_RETURN)
				fprintf(stderr, "ERROR: SSL_read() = SSL_%s\n%s", strsslerr(err), ERR_error_string(0, NULL));
			return -1;	/* FATAL */
		}
		// DEBUGF("num %d\n", num);
		ret = fwrite(buf, 1, num, fp);
		if (ret != num)
		{
			fprintf(stderr, "%s - %s\n", fname, strerror(errno));
			return -1;
		}
		DP_update(fz, cur_pos, 0);
		XASSERT(len >= num, "len %"PRIu64" < num %d\n", len, num);
		cur_pos += num;
		len -= num;
	}

	DP_update(fz, cur_pos, 1);
	DP_finish();

	fclose(fp);

	return 0;
}

/*
 * Return 0 on success.
 * Return -1 on error (FATAL. Must exit)
 * Return >0 if file was skipped.
 */
static int
client_sendfile(char *filename)
{
	PKT_CTX pkt;
	FILE *fp;
	uint64_t fz = 0xFFFFFFFFFFFFFFFF;	/* File size not known */
	int ret;
	char *fname = NULL;
	int is_pipe = 0;

	/* Check if file exists and is a valid file. */
	if (memcmp(filename, "-\000", 2) == 0)
	{
		fp = stdin;
		is_pipe = 1;
		fname = "<STDIN>";
	} else {
		fp = fopen(filename, "r");
		if (fp == NULL)
		{
			fprintf(stderr, "%s - %s\n", filename, strerror(errno));
			return 1;
		}

		struct stat res;
		ret = fstat(fileno(fp), &res);
		if (ret != 0)
		{
			fprintf(stderr, "%s - %s\n", filename, strerror(errno));
			return 1;
		}
		if (S_ISREG(res.st_mode)) DEBUGF("REG\n");
		if (S_ISLNK(res.st_mode)) DEBUGF("LNK\n");
		if (S_ISCHR(res.st_mode)) DEBUGF("CHR\n");
		if (S_ISBLK(res.st_mode)) DEBUGF("BLK\n");
		if (S_ISFIFO(res.st_mode)) DEBUGF("FIFO\n");
		if (S_ISSOCK(res.st_mode)) DEBUGF("SOCK\n");

		if (S_ISREG(res.st_mode))
		{
			/* HERE: A regular file (including a symlinked file) */
			fname = basename(filename);
			fz = res.st_size;
		}
		/* Check for likes as /dev/urandom or /dev/stdin */
		if (S_ISCHR(res.st_mode) || S_ISFIFO(res.st_mode))
		{
			fname = filename;
		}
		DEBUGF("FileSize of '%s' = %llu\n", fname, fz);

		if (fname == NULL)
		{
			fprintf(stderr, "%s - Not a regular file. SKIPPING...\n", filename);
			return 1;
		}
	}


	PKT_CTX_init(&pkt);

	/* Send a OFFER packet to the Server with filename to be send. */
	pkt_build_offer(&pkt, is_pipe?"":fname);
	ret = SSL_PKT_write(gopt.ssl, &pkt);
	// DEBUGF("OFFER send...%d\n", ret);

	/* Read a ACCEPT packet from Server to know which offset to start from. */
	ret = SSL_PKT_read(gopt.ssl, &pkt, GST_PKT_TYPE_ACCEPT);
	// DEBUGF("SSL_PKT_read: %d\n", ret);
	struct _pkt_accept *acc = (struct _pkt_accept *)pkt.buf;
	uint64_t offset = ntohll(acc->file_offset);
	DEBUGF("Remote requests to start at offset %llu\n", offset);

	if (offset == 0xFFFFFFFFFFFFFFFF)
	{
		fprintf(stderr, "%s - Rejected by peer...\n", filename);
		return 1;
	}

	uint64_t fsz_left = 0;

	DEBUGF("fz %llu offset %llu\n", fz, offset);
	if (is_pipe == 0)
	{
		if (offset > fz)
		{
			fprintf(stderr, "%s - Remote file is larger. Skipping...\n", filename);
		} else {

			ret = fseek(fp, offset, SEEK_SET);
			if (ret == 0)
			{
				fsz_left = fz - offset;
			} else {
				fprintf(stderr, "%s - fseek() %s. Skipping...\n", filename, strerror(errno));
			}
		}
	} else {
		fsz_left = 0xFFFFFFFFFFFFFFFF;
	}

	pkt_build_data(&pkt, fsz_left);
	ret = SSL_PKT_write(gopt.ssl, &pkt);

	int64_t cur_pos = fz - fsz_left;
	DP_init(strlen(fname)?fname:filename, gopt.out);
	DP_update(fz, cur_pos, 1);

	uint8_t buf[GST_READ_BUF_SIZE];
	int num;
	while (fsz_left > 0)
	{
		ret = fread(buf, 1, sizeof buf, fp);
		// DEBUGF("read %d\n", ret);
		if (ret <= 0)
			break;
		cur_pos += ret;
		DP_update(fz, cur_pos, 0);

		num = SSL_write(gopt.ssl, buf, ret);
		if (num != ret)
		{
			DEBUGF("num %d != ret %d\n", num, ret);
			break;
		}

		XASSERT(num <= fsz_left, "OOPS. CAN NOT HAPPEN %d > %"PRIu64"\n", num, fsz_left);
		fsz_left -= num;
	}

	if (fsz_left == 0)
	{
		DP_update(fz, cur_pos, 1);
	} else {
		DP_update(0, cur_pos, 1);
	}
	DP_finish();

	if ((fsz_left > 0) && (fz != 0xFFFFFFFFFFFFFFFF))
	{
		fprintf(stderr, "ERROR: Failed to transfer all data...%s\n", strerror(errno));
		return -1;	/* FATAL */
	}

	fclose(fp);

	return 0;	
}

static void
do_client(void)
{
	int ret;
	int tcp_fd;

	DEBUGF("### CLIENT ###\n");

	//GS_setsockopt(gopt.gsocket, GS_OPT_SOCKWAIT, NULL, 0);
#if 1
	VOUT(2, "=Global Socket %s.gsocket\n", gopt.gs_addr.b58str);
	VOUT(1, "=Connecting...");
	tcp_fd = GS_connect(gopt.gsocket);
	if (tcp_fd < 0)
		ERREXIT("GS_connect(): %s (Wrong Secret?)\n", GS_CTX_strerror(gopt.gsocket->ctx));
	GS_close(gopt.gsocket);
	VOUT(1, "Success!\n");
	VOUT(2, "=Global Socket Connection established\n");

#else
	// BIO *bio;

	// bio = BIO_new_connect("127.0.0.1:31338");
	// XASSERT(bio != NULL, "\n");
	// SSL_set_bio(gopt.ssl, bio, bio);

	// SSL_set_connect_state(gopt.ssl);
	int sox;

	sox = socket(PF_INET, SOCK_STREAM, 0);
	if (sox < 0)
		ERREXIT("socket(): %s\n", strerror(errno));

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(31338);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	ret = connect(sox, (struct sockaddr *)&addr, sizeof addr);
	XASSERT(ret >= 0, "connect() failed: %s\n", strerror(errno));
	tcp_fd = sox;
#endif

	SSL_set_fd(gopt.ssl, tcp_fd);

	ret = SSL_connect(gopt.ssl);
	DEBUGF("SSL_connect() = %d\n", ret);
	XASSERT(ret == 1, "SSL_read() = SSL_%s\n%s\n", strsslerr(SSL_get_error(gopt.ssl, ret)), ERR_error_string(0, NULL));
	VOUT(1, "=Encryption: %s (Prime: %s bits)\n", GST_DFL_CIPHER, GST_DFL_STRENGTH);

	PKT_CTX pctx;
	PKT_CTX_init(&pctx);

	pkt_build_helo(&pctx);
	ret = SSL_PKT_write(gopt.ssl, &pctx);
	DEBUGF("HELO sent (%d)\n", ret);

	int i;
	ret = 0;
	for (i = 0; i < gopt.n_files; i++)
	{
		ret = client_sendfile(gopt.files[i]);
		DEBUGF("client_sendfile() = %d\n", ret);
		if (ret < 0)
		{
			break;
		}
	}

	/*
	 * Graceful shutdown. Otherwise TCP-RST will kill remote TCP
	 * before all data has been read from the socket and thus end
	 * with an incomplete data transfer.
	 */
	ret = SSL_shutdown(gopt.ssl);
	if (ret == 0)
		ret = SSL_shutdown(gopt.ssl);
	DEBUGF("SSL_shutdown() = %d\n", ret);

	exit(0);
}

/*
 * Key Deriviation from a (master-)secret and kd-path
 */
static void
kd_secret(GS_ADDR *addr, char *kd_path, char *secret)
{

	size_t ssz = strlen(secret);
	size_t ksz = strlen(kd_path);
	char *buf;

	buf = malloc(ksz + ssz);
	XASSERT(buf != NULL, "malloc() failed\n");

	memcpy(buf, kd_path, ksz);
	memcpy(buf + ksz, secret, ssz);

	GS_ADDR_bin2addr(addr, buf, ksz + ssz);
	free(buf);
}

int
main(int argc, char *argv[])
{
	//DP_test();

	init_defaults();
	do_getopt(argc, argv);
	init_vars();

	if (gopt.flags & GST_FL_IS_SERVER)
		do_server();
	else
		do_client();

	exit(0);
	return 0;
}
