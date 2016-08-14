AC_INIT([libnoise], [0.1], [meson800@gmail.com])
AM_PROG_AR
LT_INIT
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_LANG([C++])
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX_11
AC_CHECK_LIB(ssl, SSL_library_init, , AC_MSG_ERROR([Cannot compile noise without libssl. Try installing the libssl and libssl-dev packages]))
AC_CHECK_LIB(crypto, OPENSSL_config, , AC_MSG_ERROR([Cannot compile noise without libcrypto. Try installing the libssl and libssl-dev packages]))
AC_CHECK_LIB(pthread, pthread_create, , AC_MSG_ERROR([Cannot compile noise without libpthread]))
AC_CHECK_HEADER([fstream], , AC_MSG_ERROR([Cannot compile noise without header "fstream"]))
AC_CHECK_HEADER([iostream], , AC_MSG_ERROR([Cannot compile noise without header "iostream"]))
AC_CHECK_HEADER([map], , AC_MSG_ERROR([Cannot compile noise without header "map"]))
AC_CHECK_HEADER([openssl/conf.h], , AC_MSG_ERROR([Cannot compile noise without header "openssl/conf.h"]))
AC_CHECK_HEADER([openssl/ec.h], , AC_MSG_ERROR([Cannot compile noise without header "openssl/ec.h"]))
AC_CHECK_HEADER([openssl/err.h], , AC_MSG_ERROR([Cannot compile noise without header "openssl/err.h"]))
AC_CHECK_HEADER([openssl/evp.h], , AC_MSG_ERROR([Cannot compile noise without header "openssl/evp.h"]))
AC_CHECK_HEADER([openssl/obj_mac.h], , AC_MSG_ERROR([Cannot compile noise without header "openssl/obj_mac.h"]))
AC_CHECK_HEADER([openssl/opensslconf.h], , AC_MSG_ERROR([Cannot compile noise without header "openssl/opensslconf.h"]))
AC_CHECK_HEADER([openssl/rand.h], , AC_MSG_ERROR([Cannot compile noise without header "openssl/rand.h"]))
AC_CHECK_HEADER([openssl/rsa.h], , AC_MSG_ERROR([Cannot compile noise without header "openssl/rsa.h"]))
AC_CHECK_HEADER([openssl/sha.h], , AC_MSG_ERROR([Cannot compile noise without header "openssl/sha.h"]))
AC_CHECK_HEADER([openssl/x509.h], , AC_MSG_ERROR([Cannot compile noise without header "openssl/x509.h"]))
AC_CHECK_HEADER([stdexcept], , AC_MSG_ERROR([Cannot compile noise without header "stdexcept"]))
AC_CHECK_HEADER([stdlib.h], , AC_MSG_ERROR([Cannot compile noise without header "stdlib.h"]))
AC_CHECK_HEADER([string], , AC_MSG_ERROR([Cannot compile noise without header "string"]))
AC_CHECK_HEADER([time.h], , AC_MSG_ERROR([Cannot compile noise without header "time.h"]))
AC_CHECK_HEADER([unistd.h], , AC_MSG_ERROR([Cannot compile noise without header "unistd.h"]))
AC_CHECK_HEADER([vector], , AC_MSG_ERROR([Cannot compile noise without header "vector"]))
AC_PROG_RANLIB
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
