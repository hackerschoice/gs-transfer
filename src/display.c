/*
 * Display progress of file transfers...
 *
 * Cient has 1 file per transfer. Server might have multiple.
 */

#include "common.h"

#define MAX_WINSIZE		(512)
#define DEFAULT_WINSIZE	(80)
#define UPDATE_INTERVAL	(500 * 1000)	/* update every 100ms 		       */
#define ALRM_UPD_INTERV	(1)				/* if we 'stall' in blocking write */
#define STALL_TIME		(5 * 1000000)	/* Stalled this many seconds       */

static int64_t end_pos;
static int64_t cur_pos;
static int64_t last_pos;
static int win_size;
static char filename[256];	/* True file name as supplied */
static char fname[256];		/* evtl shortened file name */
static double last_usec;
static double now_usec;
static double start_usec;
static long stalled;		/* how long we have been stalled */
static volatile sig_atomic_t win_resized; /* for window resizing */
static volatile sig_atomic_t alarm_fired;
static int alarm_count;
static const char unit[] = "BKMGTE";	/* Up to Exa-bytes. */
FILE *fp;

static void dp_refresh(void);

// pkt.h                                         100% 1827    40.6KB/s   00:00

static void
format_rate(char *buf, int size, int64_t bytes)
{
	int i;

	bytes *= 100;

	for (i = 0; bytes >= 100*1000 && unit[i] != 'E'; i++)
		bytes = (bytes + 512) / 1024;
	if (i == 0)
	{
		i++;
		bytes = (bytes + 512) / 1024;
	}
	snprintf(buf, size, "%3lld.%1lld%c%s",
            (long long) (bytes + 5) / 100,
            (long long) (bytes + 5) / 10 % 10,
            unit[i],
            i ? "B" : " ");
}

static void
format_size(char *buf, int size, int64_t bytes)
{
	int i;

	for (i = 0; bytes >= 10000 && unit[i] != 'E'; i++)
		bytes = (bytes + 512) / 1024;
	snprintf(buf, size, "%4lld%cB",
            (long long) bytes,
            i ? unit[i]:' ');
}

static double
get_usec(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return (double)tv.tv_sec * 1000000 + tv.tv_usec;
}

static void
sig_winch(int sig)
{
	win_resized = 1;
}

static void
sig_alarm(int sig)
{
	alarm_fired = 1;
	alarm_count++;
	now_usec = get_usec();
	dp_refresh();
	last_usec = now_usec;
	last_pos = cur_pos;
	// alarm(ALRM_UPD_INTERV);
}

static void
setscreensize(void)
{
    struct winsize winsize;

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
        winsize.ws_col != 0) {
            if (winsize.ws_col > MAX_WINSIZE)
                    win_size = MAX_WINSIZE;
            else
                    win_size = winsize.ws_col;
    } else
            win_size = DEFAULT_WINSIZE;
    win_size += 1;                                  /* trailing \0 */	
}

static void
make_fname(void)
{

	int file_len = win_size - 36;
	// DEBUGF("file_len %d\n", file_len);
	snprintf(fname, MIN(file_len, sizeof fname), "%-*s", file_len, filename);
	// DEBUGF("DISPLAY fname '%s'\n", fname);

}

void
DP_init(char *xfilename, FILE *out)
{
	end_pos = 0;
	cur_pos = 0;
	last_usec = 0;
	fp = out;

	setscreensize();

	snprintf(filename, sizeof filename, "%s", xfilename);
	make_fname();

	signal(SIGWINCH, sig_winch);
	signal(SIGALRM, sig_alarm);
}

static void
dp_refresh(void)
{
	char buf[MAX_WINSIZE + 1];
	int hours, minutes, seconds;

	if (win_resized)
	{
		win_resized = 0;
		setscreensize();
		make_fname();
		buf[0] = '\r';
		/* Delete entire row. */
		snprintf(buf + 1, sizeof buf - 1, "%-*s", win_size - 1, " ");
		fwrite(buf, 1, strlen(buf), fp);
		fflush(fp);
	}
	/* At least call us every second */
	alarm(ALRM_UPD_INTERV);

	buf[0] = '\r';

	snprintf(buf + 1, sizeof buf -1, "%s", fname);

	int64_t bytes_left;
	if (end_pos == -1)
		bytes_left = -1;
	else
		bytes_left = end_pos - cur_pos;
	double elapsed;
	double bytes_per_sec;
	int percent;

	// DEBUGF("end_pos %lld cur_pos %lld\n", end_pos, cur_pos);
	elapsed = now_usec - start_usec;
	if ((bytes_left > 0) || (bytes_left == -1))
	{
		if (now_usec == last_usec)
			bytes_per_sec = 0;
		else
			bytes_per_sec = (cur_pos - last_pos) * 1000000 / (now_usec - last_usec);
		if (bytes_left == -1)
			percent = 0;		/* Sending peer does not know size. Display 100% */
		else
			percent = ((float)cur_pos / end_pos) * 100;
	} else {
		/* Calcualte true total speed when done */
		if (cur_pos == last_pos)
			bytes_per_sec = 0;	/* File was already finished */
		else
			bytes_per_sec = end_pos * 1000000 / elapsed;
		percent = 100;
	}

	if (bytes_left == -1)
		strlcat(buf, " ???% ", win_size);
	else
		snprintf(buf + strlen(buf), win_size - strlen(buf), " %3d%% ", percent);

	format_size(buf + strlen(buf), win_size - strlen(buf), cur_pos);
	strlcat(buf, " ", win_size);

	format_rate(buf + strlen(buf), win_size - strlen(buf), (off_t)bytes_per_sec);
	strlcat(buf, "/s ", win_size);	/* per second */

	/* ETA */
	if ((cur_pos == last_pos) || (alarm_count))
	{
		bytes_per_sec = 0;
		stalled += (now_usec - last_usec);
	}
	else
		stalled = 0;
	// DEBUGF("\nstalled %ld, elapsed %f, last_usec %f, bps %f\n", stalled, elapsed, last_usec, bytes_per_sec);

	if (stalled >= STALL_TIME)
		strlcat(buf, "- stalled -", win_size);		/* Truely stalled */
	else if (bytes_per_sec == 0 && bytes_left)
		strlcat(buf, "  --:-- ETA", win_size);		/* Temporary hickup */
	else {
		if (bytes_left <= 0)
			seconds = elapsed / 1000000;
		else
			seconds = bytes_left / bytes_per_sec;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		if (hours != 0)
			snprintf(buf + strlen(buf), win_size - strlen(buf), "%d:%02d:%02d", hours, minutes, seconds);
        else
            snprintf(buf + strlen(buf), win_size - strlen(buf), "  %02d:%02d", minutes, seconds);

        if (bytes_left > 0)
                strlcat(buf, " ETA", win_size);
        else
                strlcat(buf, "    ", win_size);
	}

	fwrite(buf, 1, strlen(buf), fp);
	fflush(fp);
	/* Stop the alarm when no more data is transfered */
	/* Do this as early as possible as some seconds might laps
	 * before DP_finish() is called (after successful SSL_shutdown)
	 */
	if (bytes_left <= 0)
		signal(SIGALRM, SIG_IGN);


}

/*
 * Might call dp_refresh if enough time has expired.
 * xtotal might be -1 if the total size is not known.
 * xtotal might be 0 if no more data (and end_pos becomes cur_pos)
 */
void
DP_update(off_t xtotal, off_t xcur_pos, int force_update)
{
	if (xtotal != 0)
		end_pos = xtotal;
	if (xcur_pos != 0)
		cur_pos = xcur_pos;

	if (xtotal == 0)
		end_pos = cur_pos;

	if (fp == NULL)
		return;

	now_usec = get_usec();

	if (last_usec > 0)
	{
		/* Here: Not called for the first time. Check if display should be updated. */
		/* Update every 100ms */
		if (!force_update && (last_usec + UPDATE_INTERVAL > now_usec))
			return;
	} else {
		/* First Time */
		start_usec = now_usec;
		last_usec = now_usec;
		last_pos = cur_pos;
	}

	dp_refresh();
	alarm_count = 0;
	last_usec = now_usec;
	last_pos = cur_pos;
}

void
DP_finish(void)
{
	signal(SIGWINCH, SIG_DFL);
	fprintf(fp, "\n");
	fflush(fp);
	fp = NULL;
}

void
DP_test(void)
{
	DP_init("foobarikasjdflkjasdfjljlsa sdjf sdf .dat.daldfjlkajd alsdkjflkj flajljfaskj 1234.tar.gz", stderr);

	//off_t total = 1 * 1024 * 1024;	/* 1 MB */
	off_t total = 1 * 1024 * 1024 * 1024; /* 1GB */
	off_t cur = 0;
	int i = 0;
	while (cur < total)
	{
		i++;
		DP_update(total, cur, 0);

		if (i == 100)
		{
			sleep(5);
			sleep(5);
			sleep(5);
			sleep(5);
			sleep(5);
			sleep(5);
			sleep(5);
			sleep(5);
			sleep(5);
			sleep(5);
		}
		usleep(10*1000);
		// cur += 1024;
		cur += 23 * 1024 * 1024 / 100;
	}
	DP_update(total, cur, 1);
	DP_finish();
	exit(0);
}
