dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.61)
AC_INIT([gs-transfer], 1.0.0)
AC_CONFIG_AUX_DIR(config)
AC_CANONICAL_SYSTEM

dnl we use automake
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)
dnl for --enable-maintainer-mode fun use:
dnl AM_MAINTAINER_MODE 

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
dnl AC_PROG_RANLIB

dnl
dnl Use these compiler flags if we have gcc.
dnl
if test $ac_cv_prog_gcc = yes; then
  CCOPTS='-O2 -Wall'
  CFLAGS="$CCOPTS"
fi
test "x$prefix" != "xNONE" || prefix="/usr/local"
test "x$exec_prefix" != "xNONE" || exec_prefix="${prefix}"
trydir_i="${prefix}/include"
trydir_l="${prefix}/lib"

if test "${prefix}" != "/usr/local" ; then
	trydir_i="${trydir_i} /usr/local/include"
	trydir_l="${trydir_l} /usr/local/lib"
fi

dnl Try include paths (especially on OSX)
trydir_i="${trydir_i} /usr/local/opt/openssl/include"
for xincdir in $trydir_i ; do
	if test ! -d "$xincdir" ; then
		continue;
	fi
	if test x"${INCLUDES}" = x; then
		INCLUDES="-I${xincdir}";
	else
		INCLUDES="$INCLUDES -I${xincdir}";
	fi
done
CPPFLAGS="${INCLUDES} $CPPFLAGS"

dnl Try library paths...
trydir_l="${trydir_l} /usr/local/opt/openssl/lib"
for xlibdir in $trydir_l ; do
	if test ! -d "$xlibdir" ; then
		continue;
	fi
	if test x"${LIBDIR}" = x; then
		LIBDIR="-L${xlibdir}";
	else
		LIBDIR="$LIBDIR -L${xlibdir}";
	fi
done
LDFLAGS="${LIBDIR} $LDFLAGS"

AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, gethostbyname)
dnl AC_CHECK_LIB([m], [sqrt])
dnl AC_CHECK_LIB([net], [libnet_name_resolve], [AC_MSG_ERROR([libnet 1.0.x found. Requires libnet 1.1 or newer])])
dnl AC_CHECK_LIB([net], [libnet_init], ,[AC_MSG_ERROR([libnet 1.1.x not found])])

AC_CHECK_LIB([ssl], [SSL_new], [], [AC_MSG_ERROR([libssl not found])])
AC_CHECK_LIB([crypto], [ENGINE_init], [], [AC_MSG_ERROR([libcrypto not found])])


dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(sys/time.h unistd.h string.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_HEADER_TIME

dnl Checks for library functions.
AC_FUNC_MEMCMP

AC_TYPE_SIGNAL
dnl If size_t is not defined, define size_t to be unsigned. 
AC_TYPE_SIZE_T 
dnl If uid_t is not defined, define uid_t to be int and gid_t to be int.
AC_TYPE_UID_T

AC_CHECK_FUNCS(gettimeofday memcpy strchr strlcat)

AC_ARG_ENABLE(debug,
[  --enable-debug          Enable debug information],
	AC_DEFINE(DEBUG, 1, [Debug infos])
)

AC_ARG_ENABLE(dist,
[  --enable-dist           Enable distribution mode, Use own libraries.],
	[DIST="yes"], [DIST="no"]
)

AC_ARG_ENABLE(static,
[  --enable-static          Compile static binary],
	[STATIC="yes"], [STATIC="no"]
)

if test x"$STATIC" = x"yes"; then
	CFLAGS="-static ${CFLAGS}"
fi

AC_OUTPUT([Makefile src/Makefile])

dnl Just to show the correct values...
dnl CFLAGS="`${srcdir}/pcre-3.9/pcre-config --cflags` `${srcdir}/Libnet-1.0.2a/libnet-config --cflags --defines | tr '\n' ' '` $CFLAGS"
dnl LIBS="`${srcdir}/pcre-3.9/pcre-config --libs` `${srcdir}/Libnet-1.0.2a/libnet-config --libs` $LIBS"

echo "
${PACKAGE_NAME}-${PACKAGE_VERSION} has been configured:

 Host..............: ${host}
 Compiler..........: ${CC}
 Compiler flags....: ${CFLAGS}
 Preprocessor flags: ${CPPFLAGS}
 Linker flags......: ${LDFLAGS}
 Libraries.........: ${LIBS}

Configuration complete. Now type: make all install; ${PACKAGE_NAME} -h"


