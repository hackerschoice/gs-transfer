

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t size);
#endif

#ifndef htonll
# define htonll(n)	(((uint64_t)htonl(n)) << 32) + htonl(n >> 32)
#endif 
#ifndef ntohll
# define ntohll(n)      (((uint64_t)ntohl(n)) << 32) + ntohl(n >> 32)
#endif
