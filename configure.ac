#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT(data-ipa, 1.0.0)
AM_INIT_AUTOMAKE(data-ipa, 1.0.0)
AC_OUTPUT(Makefile ipacm/src/Makefile)
AC_CONFIG_SRCDIR([ipacm/src/IPACM_Main.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_CXX

PKG_CHECK_MODULES([LIBXML], [libxml-2.0])
AC_SUBST([LIBXML_CFLAGS])
AC_SUBST([LIBXML_LIBS])

CPPFLAGS="${CPPFLAGS} -DFEATURE_IPACM_UL_FIREWALL -DFEATURE_IPACM_PER_CLIENT_STATS -DFEATURE_VLAN_MPDN -DFEATURE_L2TP -DFEATURE_SOCKSv5"
CFLAGS="${CFLAGS} -DFEATURE_IPACM_UL_FIREWALL -DFEATURE_IPACM_PER_CLIENT_STATS -DFEATURE_VLAN_MPDN -DFEATURE_L2TP -DFEATURE_SOCKSv5"

# Checks for libraries.

AC_ARG_WITH(sanitized-headers,
      AS_HELP_STRING([--with-sanitized-headers=DIR],
         [Specify the location of the sanitized Linux headers]),
      [CPPFLAGS="$CPPFLAGS -idirafter $withval"])
AM_CONDITIONAL(KERNELMODULES, [test -n -eq 0])

AC_ARG_WITH(ipanat-headers,
      AS_HELP_STRING([--with-ipanat-headers=DIR],
         [Specify the location of the ipanat headers]),
      [CPPFLAGS="$CPPFLAGS -idirafter $withval"])

AC_ARG_WITH([dltlogging],
        AC_HELP_STRING([--with-dltlogging], [with DLT logging enabled]))

AM_CONDITIONAL(USE_DLT, test "x${with_dltlogging}" = "xyes")

if (test "x${with_dltlogging}" = "xyes"); then
        PKG_CHECK_MODULES([DLTLOG], [automotive-dlt])
        AC_SUBST([DLTLOG_CFLAGS])
        AC_SUBST([DLTLOG_LIBS])
fi

AC_ARG_WITH([glib],
      AC_HELP_STRING([--with-glib],
         [enable glib, building HLOS systems which use glib]))

if (test "x${with_glib}" = "xyes"); then
        AC_DEFINE(ENABLE_USEGLIB, 1, [Define if HLOS systems uses glib])
        PKG_CHECK_MODULES(GTHREAD, gthread-2.0 >= 2.16, dummy=yes,
                                AC_MSG_ERROR(GThread >= 2.16 is required))
        PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.16, dummy=yes,
                                AC_MSG_ERROR(GLib >= 2.16 is required))
        GLIB_CFLAGS="$GLIB_CFLAGS $GTHREAD_CFLAGS"
        GLIB_LIBS="$GLIB_LIBS $GTHREAD_LIBS"
        AC_SUBST(GLIB_CFLAGS)
        AC_SUBST(GLIB_LIBS)
fi

AM_CONDITIONAL(USE_GLIB, test "x${with_glib}" = "xyes")

has_libnl_ver=0
# libnl-2 provides only libnl-2.0.pc file, so we check for separate libnl-genl-3.0.pc
# pkg-config file just for libnl-3.0 case.
#
PKG_CHECK_MODULES([LIBNL], [libnl-3.0 >= 3.0 libnl-genl-3.0 >= 3.0], [has_libnl_ver=3], [
    PKG_CHECK_MODULES([LIBNL], [libnl-2.0 >= 2.0], [has_libnl_ver=2], [
            PKG_CHECK_MODULES([LIBNL], [libnl-1], [has_libnl_ver=1], [has_libnl_ver=0])])])

if (test "$has_libnl_ver" -eq 0); then
         AC_MSG_ERROR(libnl and libnl-genl are required but were not found)
fi

if (test "$has_libnl_ver" -gt 1); then
         AC_DEFINE([HAVE_LIBNL20], [1], [Define if you have libnl-2.0 or higher])
fi

if (test "$has_libnl_ver" -gt 2); then
         AC_DEFINE([HAVE_LIBNL30], [1], [Define if you have libnl-3.0 or higher])
fi
AC_SUBST([LIBNL_CFLAGS])

AC_SUBST([LIBNL_LIBS])

AC_ARG_ENABLE(target,
    [AS_HELP_STRING([--enable-target=TARGET], [Specify the target product to build])],
    [TARGET=$enableval],
    [TARGET=none]
)

AC_ARG_ENABLE(baseproduct,
  [AS_HELP_STRING([--enable-baseproduct=BASEPRODUCT], [Specify the base product to build])],
  [BASEPRODUCT=$enableval],
  [BASEPRODUCT=none]
)

if test "x$TARGET" = "xsdx20"; then
    echo "\n UL firewall feature enabled\n"
    CPPFLAGS="${CPPFLAGS} -DFEATURE_IPACM_UL_FIREWALL -DFEATURE_IPACM_PER_CLIENT_STATS"
    CFLAGS="${CFLAGS} -DFEATURE_IPACM_UL_FIREWALL -DFEATURE_IPACM_PER_CLIENT_STATS"
fi

if test "x$TARGET" = "xsdxpoorwills"; then
    echo "\n UL firewall feature enabled\n"
    CPPFLAGS="${CPPFLAGS} -DFEATURE_IPACM_UL_FIREWALL -DFEATURE_IPACM_PER_CLIENT_STATS -DFEATURE_VLAN_MPDN -DFEATURE_L2TP"
    CFLAGS="${CFLAGS} -DFEATURE_IPACM_UL_FIREWALL -DFEATURE_IPACM_PER_CLIENT_STATS -DFEATURE_VLAN_MPDN -DFEATURE_L2TP"
fi

if test "x$TARGET" = "xsdxprairie"; then
    echo "\n UL firewall feature enabled\n"
    CPPFLAGS="${CPPFLAGS} -DFEATURE_IPACM_UL_FIREWALL -DFEATURE_IPACM_PER_CLIENT_STATS -DFEATURE_VLAN_MPDN -DFEATURE_L2TP -DFEATURE_SOCKSv5 -DFEATURE_IPACM_RESTART"
    CFLAGS="${CFLAGS} -DFEATURE_IPACM_UL_FIREWALL -DFEATURE_IPACM_PER_CLIENT_STATS -DFEATURE_VLAN_MPDN -DFEATURE_L2TP -DFEATURE_SOCKSv5 -DFEATURE_IPACM_RESTART"
fi

if test "x$TARGET" = "xsa525"; then
    echo "\n UL firewall feature enabled\n"
    CPPFLAGS="${CPPFLAGS} -DFEATURE_IPACM_UL_FIREWALL -DFEATURE_IPACM_PER_CLIENT_STATS -DFEATURE_VLAN_MPDN -DFEATURE_L2TP -DFEATURE_SOCKSv5"
    CFLAGS="${CFLAGS} -DFEATURE_IPACM_UL_FIREWALL -DFEATURE_IPACM_PER_CLIENT_STATS -DFEATURE_VLAN_MPDN -DFEATURE_L2TP -DFEATURE_SOCKSv5 -DFEATURE_IPACM_RESTART"
fi

if test "x$TARGET" = "xsa525m"; then
    echo "\n UL firewall feature enabled\n"
    CPPFLAGS="${CPPFLAGS} -DFEATURE_IPACM_UL_FIREWALL -DFEATURE_IPACM_PER_CLIENT_STATS -DFEATURE_VLAN_MPDN -DFEATURE_L2TP -DFEATURE_SOCKSv5"
    CFLAGS="${CFLAGS} -DFEATURE_IPACM_UL_FIREWALL -DFEATURE_IPACM_PER_CLIENT_STATS -DFEATURE_VLAN_MPDN -DFEATURE_L2TP -DFEATURE_SOCKSv5 -DFEATURE_IPACM_RESTART"
fi

if test "x$BASEPRODUCT" = "xauto"; then
	CPPFLAGS="${CPPFLAGS} -DDATA_CONFIG_DIR_PATH='\"/etc/data\"' -DSYSRW_CONFIG_DIR_PATH='\"/systemrw/data\"'"
	CFLAGS="${CFLAGS} -DDATA_CONFIG_DIR_PATH='\"/etc/data\"' -DSYSRW_CONFIG_DIR_PATH='\"/systemrw/data\"'"
fi

AM_CONDITIONAL(NO_L2TP, test "x$TARGET" = "xsdx20" || test "x$TARGET" = "xsdxpoorwills")

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h netinet/in.h sys/ioctl.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_OFF_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([memset munmap])

AC_OUTPUT
