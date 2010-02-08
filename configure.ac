#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([erlang-pwd], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([priv/pwd_drv.h])
#AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lei':
AC_CHECK_LIB([ei], [main])
# FIXME: Replace `main' with a function in `-lerl_interface':
AC_CHECK_LIB([erl_interface], [main])

# Checks for header files.
AC_CHECK_HEADERS([string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([endpwent])

AC_ERLANG_NEED_ERLC
AC_ERLANG_SUBST_ROOT_DIR
AC_ERLANG_SUBST_LIB_DIR
AC_ERLANG_CHECK_LIB(erl_interface)

AC_CONFIG_FILES([Makefile
                 priv/Makefile])
AC_OUTPUT
