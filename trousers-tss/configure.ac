#
# configure.in for the trousers project
#

AC_INIT(trousers, 0.3.14, trousers-tech@lists.sf.net)

TSS_SPEC_MAJOR=1
TSS_SPEC_MINOR=2
TSS_VER_MAJOR=0
TSS_VER_MINOR=3

# compute $target
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([foreign subdir-objects 1.6])

# Debugging support
AC_ARG_ENABLE([debug],
    [AC_HELP_STRING([--enable-debug], [turn on all trousers debugging flags [default=off]])],
    AC_MSG_RESULT([*** Enabling debugging at user request ***]),)

# If the user has not set CFLAGS, do something appropriate
test_CFLAGS=${CFLAGS+set}
if test "$test_CFLAGS" != set; then
	if test "x$enable_debug" = "xyes"; then
		CFLAGS="-O0 -g -DTSS_DEBUG -Wreturn-type"
#		CFLAGS="-O0 -g -DTSS_DEBUG -Wreturn-type -DTCSD_SINGLE_THREAD_DEBUG"
	else
		CFLAGS="-O2"
	fi
else
	if test "x$enable_debug" = "xyes"; then
		CFLAGS="${CFLAGS} -O0 -g -DTSS_DEBUG -Wreturn-type"
	fi
fi

# Arch specific stuff
case $target in
	*darwin*)
        	TCSD_LDFLAGS=""
        	;;
	*solaris*)
		CFLAGS="$CFLAGS -DSOLARIS"
		;;
        *)
        	TCSD_LDFLAGS="-pie -Wl,-z,relro -Wl,-z,now"
                ;;
esac

AC_SUBST(TCSD_LDFLAGS)

# Non-standard OpenSSL location
AC_MSG_CHECKING([Non-standard OpenSSL location])
AC_ARG_WITH(openssl,
	AC_HELP_STRING([--with-openssl=PATH], [Location of openssl libs/includes]),
	[OPENSSL_INCLUDE_DIR="$withval/include"
	 OPENSSL_LIB_DIR="$withval/lib"
	 if [[ ! -d $OPENSSL_INCLUDE_DIR -o ! -d $OPENSSL_LIB_DIR ]]; then
		AC_MSG_ERROR([$OPENSSL_INCLUDE_DIR or $OPENSSL_LIB_DIR doen't exist!])
	 else
		AC_MSG_RESULT([yes])
		CFLAGS="$CFLAGS -L$OPENSSL_LIB_DIR -I$OPENSSL_INCLUDE_DIR"
		AC_SUBST([OPENSSL_LIB_DIR])
	 fi],
	[AC_MSG_RESULT([no])
	 AC_SUBST([OPENSSL_LIB_DIR], []) ] )

# The tspi Makefile will look for trspi/crypto/@CRYPTO_PACKAGE@/crypto.c
# Future crypto packages can go in their own subdir of trspi/crypto
# and a check for them should be made here
AC_CHECK_LIB([crypto], [EVP_DigestUpdate],
		[CRYPTO_PACKAGE='openssl'],
		[AC_MSG_ERROR([openssl is currently the only supported crypto library for trousers. Please install openssl from http://www.openssl.org or the -devel package from your distro])])
AC_SUBST([CRYPTO_PACKAGE])
AC_SUBST(CRYPTOLIB, -lcrypto)

AC_ARG_ENABLE(gcov,
		[AC_HELP_STRING([--enable-gcov], [turn on gcov code coverage flags [default=off]])],
		[CFLAGS="$CFLAGS -ftest-coverage -fprofile-arcs"
		 AC_MSG_RESULT([*** Enabling gcov at user request ***])],)

# profiling support
AC_ARG_ENABLE(gprof,
		[AC_HELP_STRING([--enable-gprof], [enable profiling with gprof [default=off]])],
		[CFLAGS="$CFLAGS -pg"
		 AC_MSG_RESULT([*** Enabling profiling at user request ***])],)

SPEC_COMP=0
# strict spec compliance
AC_ARG_ENABLE(strict-spec-compliance,
		[AC_HELP_STRING([--enable-strict-spec-compliance], [build TrouSerS as strictly spec compliant [default=off]])],
		[CFLAGS="$CFLAGS -DTSS_SPEC_COMPLIANCE"
		 SPEC_COMP=1
		 AC_MSG_RESULT([*** Enabling spec compliance at user request ***])],)

# user+group checking
AC_ARG_ENABLE(usercheck,
		[AC_HELP_STRING([--disable-usercheck], [build TrouSerS without checking and setting of user/group tss [default=on] (Caution: This is intended for development purposes only.)])],
		[AS_IF([test "x$enableval" = "xno"], [CFLAGS="$CFLAGS -DNOUSERCHECK"
		AC_MSG_RESULT([*** Disabling user checking at user request ***])])],)
AM_CONDITIONAL(NOUSERCHECK, [test "x$enable_usercheck" = "xno"])

# daa math lib: gmp or openssl (default openssl)
MATH_DEFINE=BI_OPENSSL
AC_ARG_WITH([gmp],
	    AC_HELP_STRING([--with-gmp], [build TrouSerS with the GMP math lib (used in DAA)]),
		[AC_CHECK_LIB(gmp, [__gmp_rand], [], [])
		AC_CHECK_HEADERS([gmp.h])
	    MATH_DEFINE=BI_GMP
		AC_MSG_RESULT([*** Enabling GMP lib at user request ***]) ]
)

case "$MATH_DEFINE" in
BI_OPENSSL)
	AC_CHECK_HEADERS([ openssl/bn.h openssl/engine.h])
	;;
esac
CFLAGS="$CFLAGS -D$MATH_DEFINE"

GUI=openssl
AC_ARG_WITH(gui,
	    [AC_HELP_STRING([--with-gui], [type of gui popup (gtk/none) [default=gtk]])],
	    [GUI=$withval],
	    [])

if test "x$GUI" = "xgtk"; then
	# section imported from Glade compile
	pkg_modules="gtk+-2.0 >= 2.0.0"
	PKG_CHECK_MODULES(GTK,
		[$pkg_modules],
		AM_CONDITIONAL(HAVE_GTK, true),
		[AM_CONDITIONAL(HAVE_GTK, false)
		AC_MSG_ERROR([Please install the gtk2-devel package for your distro or select another gui option.]) ])
	AM_CONDITIONAL(OPENSSL_UI, false)
	AC_SUBST(GTK_CFLAGS)
	AC_SUBST(GTK_LIBS)
elif test "x$GUI" = "xopenssl"; then
	# We know we have OpenSSL
	AM_CONDITIONAL(OPENSSL_UI, true)
	AM_CONDITIONAL(HAVE_GTK, false)
elif test "x$GUI" = "xnone"; then
	if test $SPEC_COMP -eq 1; then
		AC_MSG_ERROR([Popups must be enabled in strict spec compliance mode])
	fi
	AC_MSG_RESULT([*** Disabling GUI popups at user request ***])
	AC_MSG_RESULT([*** WARNING: This may break apps! ***])
	CFLAGS="$CFLAGS -DTSS_NO_GUI"
	AM_CONDITIONAL(HAVE_GTK, false)
	AM_CONDITIONAL(OPENSSL_UI, false)
else
	AC_MSG_ERROR(["gtk", "openssl" and "none" are the only supported gui options for trousers])
fi

#
# The default port that the TCS daemon listens on
#
AC_SUBST(TCSD_DEFAULT_PORT, 30003)
#
# The RPC mechanism to build into both libtspi and the tcsd
#
# AC_SUBST(RPC, "soap")
AC_SUBST(RPC, "tcstp")

#
# API= The TSS API level to build by default.
#
# To build a 1.1 TSS, set API=1.1 (./configure --with-api=1.1)
# To build a 1.2 TSS, set API=1.2 (./configure --with-api=1.2)
#
# In order to build a custom TSS API, set API to the lowest API level that
# contains the APIs you need. For instance, if you need only APIs that are
# a subset of the TSS 1.1 API, set this to 1.1. If you need any of the 1.2
# APIs, you'll need to set this to 1.2. Send mail to trousers-tech@lists.sf.net
# if you have questions.
#
API=1.2
AC_ARG_WITH(api,
	    [AC_HELP_STRING([--with-api], [Version of the TSS API to build [default=1.2]])],
	    [API=$withval],
	    [])

if test "x$API" != "x1.1" && test "x$API" != "x1.2"; then
	AC_MSG_ERROR(["1.1" and "1.2" are the only supported API versions for trousers.
		      Custom API build options are available by editing 'configure.in'.])
fi

if test "x$API" = "x1.1" || test "x$API" = "x1.2"; then
	# Tspi_Hash_GetHashValue,SetHashValue,UpdateHashValue
	AM_CONDITIONAL(TSS_BUILD_HASH, true)
	# Tspi_{Get|Set}Attribdata,{Get|Set}AttribUint32
	AM_CONDITIONAL(TSS_BUILD_GETSET, true)
	# Tspi_TPM_GetRandom,StirRandom
	AM_CONDITIONAL(TSS_BUILD_RANDOM, true)
	# Tspi_GetCapability (for TSP and TCS capabilities)
	AM_CONDITIONAL(TSS_BUILD_CAPS, true)
	# Tspi_TPM_GetCapability (for TPM chip capabilities)
	AM_CONDITIONAL(TSS_BUILD_CAPS_TPM, true)
	# Tspi_GetPolicyObject, Tspi_Policy_SetSecret,FlushSecret,AssignToObject
	AM_CONDITIONAL(TSS_BUILD_POLICY, true)
	# Tspi_TPM_DirWrite,DirRead
	AM_CONDITIONAL(TSS_BUILD_DIR, true)
	# Tspi_TPM_GetEvent,GetEvents,GetEventLog
	AM_CONDITIONAL(TSS_BUILD_PCR_EVENTS, true)
	# Tspi_Hash_Sign,VerifySignature
	AM_CONDITIONAL(TSS_BUILD_SIGN, true)
	# Tspi_TPM_Quote
	AM_CONDITIONAL(TSS_BUILD_QUOTE, true)
	# Tspi_PcrComposite_{Set|Get}PcrValue,SelectPcrIndex
	AM_CONDITIONAL(TSS_BUILD_PCR_COMP, true)
	# Tspi_Data_Seal,Unseal
	AM_CONDITIONAL(TSS_BUILD_SEAL, true)
	# Tspi_ChangeAuth,ChangeAuthAsym
	AM_CONDITIONAL(TSS_BUILD_CHANGEAUTH, true)
	# Tspi_Data_Bind,Unbind
	AM_CONDITIONAL(TSS_BUILD_BIND, true)
	# Tspi_TPM_TakeOwnership,ClearOwner (REQ: EK)
	AM_CONDITIONAL(TSS_BUILD_OWN, true)
	# Tspi_TPM_CreateEndorsementKey,GetPubEndorsementKey
	AM_CONDITIONAL(TSS_BUILD_EK, true)
	# Tspi_Context_RegisterKey,UnregisterKey,LoadKeyByUUID,GetKeyByUUID,GetKeyByPublicInfo,
	# GetRegisteredKeysByUUID
	AM_CONDITIONAL(TSS_BUILD_PS, true)
	# Tspi_TPM_{Set|Get}Status
	AM_CONDITIONAL(TSS_BUILD_ADMIN, true)
	# Tspi_TPM_CollateIdentityRequest,ActivateIdentity
	AM_CONDITIONAL(TSS_BUILD_AIK, true)
	# Tspi_Key_CertifyKey
	AM_CONDITIONAL(TSS_BUILD_CERTIFY, true)
	# Tspi_TPM_CreateMaintenanceArchive,KillMaintenanceFeature,LoadMaintenancePubKey,
	# CheckMaintenancePubKey
	AM_CONDITIONAL(TSS_BUILD_MAINT, true)
	# Tspi_TPM_AuthorizeMigrationTicket,Key_CreateMigrationBlob,ConvertMigrationBlob
	AM_CONDITIONAL(TSS_BUILD_MIGRATION, true)
	# Tspi_Context_LoadKeyByBlob,Key_LoadKey,UnloadKey,CreateKey,WrapKey,GetPubKey
	AM_CONDITIONAL(TSS_BUILD_KEY, true)
	# Tspi_TPM_PcrExtend,PcrRead,PcrReset
	AM_CONDITIONAL(TSS_BUILD_PCR_EXTEND, true)
	# Tspi_TPM_SelfTestFull,CertifySelfTest,GetTestResult
	AM_CONDITIONAL(TSS_BUILD_SELFTEST, true)
fi

if test "x$API" = "x1.2"; then
	AM_CONDITIONAL(TSS_BUILD_TSS12, true)
	# Don't build DAA until the API is fixed - KEY
	AM_CONDITIONAL(TSS_BUILD_DAA, true)
	AM_CONDITIONAL(TSS_BUILD_PCR_COMP12, true)
	AM_CONDITIONAL(TSS_BUILD_COUNTER, true)
	AM_CONDITIONAL(TSS_BUILD_TICK, true)
	AM_CONDITIONAL(TSS_BUILD_TRANSPORT, true)
	AM_CONDITIONAL(TSS_BUILD_ASN1, true)
	AM_CONDITIONAL(TSS_BUILD_NV, true)
	AM_CONDITIONAL(TSS_BUILD_AUDIT, true)
	AM_CONDITIONAL(TSS_BUILD_SEALX, true)
	AM_CONDITIONAL(TSS_BUILD_DELEGATION, true)
	AM_CONDITIONAL(TSS_BUILD_QUOTE2, true)
	# CMK depends on MIGRATION
	AM_CONDITIONAL(TSS_BUILD_CMK, true)
else
	AM_CONDITIONAL(TSS_BUILD_TSS12, false)
	AM_CONDITIONAL(TSS_BUILD_DAA, false)
	AM_CONDITIONAL(TSS_BUILD_PCR_COMP12, false)
	AM_CONDITIONAL(TSS_BUILD_COUNTER, false)
	AM_CONDITIONAL(TSS_BUILD_TICK, false)
	AM_CONDITIONAL(TSS_BUILD_TRANSPORT, false)
	AM_CONDITIONAL(TSS_BUILD_ASN1, false)
	AM_CONDITIONAL(TSS_BUILD_NV, false)
	AM_CONDITIONAL(TSS_BUILD_AUDIT, false)
	AM_CONDITIONAL(TSS_BUILD_SEALX, false)
	AM_CONDITIONAL(TSS_BUILD_DELEGATION, false)
	AM_CONDITIONAL(TSS_BUILD_QUOTE2,false)
	AM_CONDITIONAL(TSS_BUILD_CMK, false)
fi

#
# There's no need to edit anything below, these conditionals control the building
# of files that support the files above, which all contain TSS APIs
#
AM_CONDITIONAL(TSS_BUILD_NV_LIST, test -z $TSS_BUILD_NV_TRUE)
AM_CONDITIONAL(TSS_BUILD_NV_SUPPORT, test -z $TSS_BUILD_NV_TRUE)
AM_CONDITIONAL(TSS_BUILD_GET_FLAGS, test -z $TSS_BUILD_ADMIN_TRUE || \
				    test -z $TSS_BUILD_CAPS_TPM_TRUE)
AM_CONDITIONAL(TSS_BUILD_PCRS_LIST, test -z $TSS_BUILD_SEAL_TRUE || \
				    test -z $TSS_BUILD_QUOTE_TRUE || \
				    test -z $TSS_BUILD_PCRS_TRUE || \
				    test -z $TSS_BUILD_PCR_COMP_TRUE || \
				    test -z $TSS_BUILD_SEALX_TRUE)
AM_CONDITIONAL(TSS_BUILD_HASH_LIST, test -z $TSS_BUILD_SIGN_TRUE || test -z $TSS_BUILD_HASH_TRUE)
AM_CONDITIONAL(TSS_BUILD_ENCDATA_LIST, test -z $TSS_BUILD_SEAL_TRUE || \
				       test -z $TSS_BUILD_CHANGEAUTH_TRUE || \
				       test -z $TSS_BUILD_BIND_TRUE || \
				       test -z $TSS_BUILD_SEALX_TRUE)
AM_CONDITIONAL(TSS_BUILD_RSAKEY_LIST, test -z $TSS_BUILD_ADMIN_TRUE || \
				      test -z $TSS_BUILD_EK_TRUE || \
				      test -z $TSS_BUILD_MIGRATION_TRUE || \
				      test -z $TSS_BUILD_MAINT_TRUE || \
				      test -z $TSS_BUILD_CERTIFY_TRUE || \
				      test -z $TSS_BUILD_AIK_TRUE || \
				      test -z $TSS_BUILD_QUOTE_TRUE || \
				      test -z $TSS_BUILD_BIND_TRUE || \
				      test -z $TSS_BUILD_CHANGEAUTH_TRUE || \
				      test -z $TSS_BUILD_OWN_TRUE || \
				      test -z $TSS_BUILD_SIGN_TRUE || \
				      test -z $TSS_BUILD_PS_TRUE || \
				      test -z $TSS_BUILD_SEAL_TRUE || \
				      test -z $TSS_BUILD_DAA_TRUE || \
				      test -z $TSS_BUILD_KEY_TRUE || \
				      test -z $TSS_BUILD_SEALX_TRUE)
AM_CONDITIONAL(TSS_BUILD_AUTH, test -z $TSS_BUILD_HASH_TRUE || \
			       test -z $TSS_BUILD_CAPS_TRUE || \
			       test -z $TSS_BUILD_CAPS_TPM_TRUE || \
			       test -z $TSS_BUILD_POLICY_TRUE || \
			       test -z $TSS_BUILD_DIR_TRUE || \
			       test -z $TSS_BUILD_PCR_EVENTS_TRUE || \
			       test -z $TSS_BUILD_SIGN_TRUE || \
			       test -z $TSS_BUILD_QUOTE_TRUE || \
			       test -z $TSS_BUILD_PCR_COMP_TRUE || \
			       test -z $TSS_BUILD_SEAL_TRUE || \
			       test -z $TSS_BUILD_SEALX_TRUE || \
			       test -z $TSS_BUILD_CHANGEAUTH_TRUE || \
			       test -z $TSS_BUILD_BIND_TRUE || \
			       test -z $TSS_BUILD_OWN_TRUE || \
			       test -z $TSS_BUILD_PS_TRUE || \
			       test -z $TSS_BUILD_ADMIN_TRUE || \
			       test -z $TSS_BUILD_AIK_TRUE || \
			       test -z $TSS_BUILD_EK_TRUE || \
			       test -z $TSS_BUILD_CERTIFY_TRUE || \
			       test -z $TSS_BUILD_MAINT_TRUE || \
			       test -z $TSS_BUILD_MIGRATION_TRUE || \
			       test -z $TSS_BUILD_KEY_TRUE || \
			       test -z $TSS_BUILD_PCR_EXTEND_TRUE || \
			       test -z $TSS_BUILD_SELFTEST_TRUE || \
			       test -z $TSS_BUILD_DAA_TRUE)
AM_CONDITIONAL(TSS_BUILD_ASYM_CRYPTO, test -z $TSS_BUILD_AIK_TRUE || \
				      test -z $TSS_BUILD_CERTIFY_TRUE || \
				      test -z $TSS_BUILD_QUOTE_TRUE || \
				      test -z $TSS_BUILD_EK_TRUE || \
				      test -z $TSS_BUILD_CHANGEAUTH_TRUE || \
				      test -z $TSS_BUILD_BIND_TRUE || \
				      test -z $TSS_BUILD_OWN_TRUE || \
				      test -z $TSS_BUILD_SELFTEST_TRUE || \
				      test -z $TSS_BUILD_SIGN_TRUE || \
				      test -z $TSS_BUILD_KEY_TRUE || \
				      test -z $TSS_BUILD_DAA_TRUE)
AM_CONDITIONAL(TSS_BUILD_SYM_CRYPTO, test -z $TSS_BUILD_AIK_TRUE || \
				     test -z $TSS_BUILD_TRANSPORT_TRUE)

#GETTEXT_PACKAGE=trousers
#AC_SUBST(GETTEXT_PACKAGE)
#AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE")

dnl Add the languages which your application supports here.
#ALL_LINGUAS=""
#AM_GLIB_GNU_GETTEXT

# end Glade section

AC_CHECK_HEADER(pthread.h, [AC_DEFINE(HAVE_PTHREAD_H, 1, [pthread header])])

AC_DISABLE_STATIC
AC_PROG_CC
AC_PROG_LIBTOOL

AC_C_BIGENDIAN([AC_DEFINE(_BIG_ENDIAN, 1, [big-endian host])])
AC_CHECK_DECL(htole32, [AC_DEFINE(HTOLE_DEFINED, 1, [htole32 function is available])])
AC_CHECK_HEADER(sys/byteorder.h, [AC_DEFINE(HAVE_BYTEORDER_H, 1, [sys/byteorder.h header])])
AC_CHECK_FUNC(daemon, [ AC_DEFINE(HAVE_DAEMON, 1, [daemon function is available]) ])
 
if test "x${GCC}" = "xyes"; then
	CFLAGS="$CFLAGS -W -Wall -Wno-unused-parameter -Wsign-compare"
fi

CFLAGS="$CFLAGS -I../include \
	-DTCSD_DEFAULT_PORT=${TCSD_DEFAULT_PORT} -DTSS_VER_MAJOR=${TSS_VER_MAJOR} \
	-DTSS_VER_MINOR=${TSS_VER_MINOR} -DTSS_SPEC_MAJOR=${TSS_SPEC_MAJOR} \
	-DTSS_SPEC_MINOR=${TSS_SPEC_MINOR}"
#CFLAGS="$CFLAGS -I../include -std=c99 -pedantic -W -Wall"
KERNEL_VERSION=`uname -r`
AC_SUBST(CFLAGS)

# When we build the rpms, prefix will be /usr. This'll do some things that make sense,
# like put our sbin stuff in /usr/sbin and our library in /usr/lib. It'll do some other
# things that don't make sense like put our config file in /usr/etc. So, I'll just hack
# it here. If the --prefix option isn't specified during configure, let it all go to
# /usr/local, even /usr/local/etc. :-P
if test x"${prefix}" = x"/usr"; then
	sysconfdir="/etc"
	localstatedir="/var"
	mandir="/usr/share/man"
elif test x"${prefix}" = x"NONE"; then
	localstatedir="/usr/local/var"
fi

AC_OUTPUT(dist/tcsd.conf \
	  dist/fedora/trousers.spec \
	  dist/trousers.spec \
	  Makefile \
	  src/Makefile \
	  src/include/Makefile \
	  src/tcs/Makefile \
	  src/tddl/Makefile \
	  src/tspi/Makefile \
	  src/trspi/Makefile \
	  src/tcsd/Makefile \
	  src/tspi/daa/Makefile \
	  man/man8/tcsd.8 \
	  man/man5/tcsd.conf.5 \
	  dist/Makefile \
	  man/Makefile \
	  man/man3/Makefile \
	  man/man5/Makefile \
	  man/man8/Makefile)

echo "CFLAGS=$CFLAGS"

