bin_PROGRAMS= issuer_setup test_join  test_sign
#key_verification test test_tpm test_join test_sign

#test_SOURCES=big_integer/bi_gmp.c big_integer/bi_openssl.c big_integer/bi.c utils/list.c big_integer/test/test.c big_integer/test/multi_exp.c
#test_CFLAGS=-I../../include/daa -I../../include -DBI_DEBUG -g -DAPPID=\"BI\"
#test_LDFLAGS=-lcrypto -lgmp
#obj_daa_SOURCES= obj_daa.c
#obj_daa_CFLAGS=-I../../include/daa -I../../include -DBI_DEBUG -DAPPID=\"DAA_ISSUER_SETUP\"
#obj_daa_LDFLAGS= -lcrypto

issuer_setup_SOURCES = daa_issuer/issuer_setup.c daa_structs.c big_integer/bi_gmp.c big_integer/bi.c daa_debug.c utils/list.c daa_parameter.c ../obj_daa.c ../../include/tss/tspi.h
issuer_setup_CFLAGS=-I../../include/daa -I../../include -I../../include/tss -DTSS_DEBUG -DBI_DEBUG -DAPPID=\"DAA_JOIN\" -DTSS_BUILD_DAA
#issuer_setup_LDFLAGS=-DTSS_DEBUG -DBI_DEBUG -DBI_H -DBI_GMP -DLIST_H -DOBJ_DAA_H -lgmp -lcrypto -lssl -ltspi -ldaa
issuer_setup_LDADD=${top_builddir}/src/tcs/libtcs.a  ${top_builddir}/src/tspi/libtspi.la -lgmp -lcrypto

#key_verification_SOURCES=daa_issuer/key_verification.c
#key_verification_CFLAGS=-I../../include/daa -I../../include -DBI_DEBUG -DAPPID=\"DAA_KEY_VERIFICATION\"
#key_verification_LDFLAGS=-lcrypto -lgmp -ltspi
#../libdaa.la

test_tpm_SOURCES = daa_platform/test.c
test_tpm_CFLAGS=-I../../include/daa -I../../include  -D_LINUX -DTSS_BUILD_DAA -DTSS_LIB_IS_12 -DTSS_DEBUG -DBI_GMP -DOBJ_DAA_H -DAPPID=\"DAA_JOIN\"  -lgmp -ltspi
test_tpm_LDFLAGS=-DTSS_DEBUG -DBI_DEBUG -DTSS_PLATFORM_H -DTSS_BUILD_DAA -DBI_H -DBI_GMP -DLIST_H -DOBJ_DAA_H  -lcrypto -lgmp ../libdaa.la

test_join_SOURCES = daa_platform/test_join.c daa_structs.c big_integer/bi_gmp.c big_integer/bi.c daa_debug.c utils/list.c daa_parameter.c ../obj_daa.c ../../include/tss/tspi.h
test_join_CFLAGS=-I../../include/daa -I../../include -I../../include/tss -DTSS_DEBUG -DBI_DEBUG -DAPPID=\"DAA_JOIN\" -DTSS_BUILD_DAA
test_join_LDADD=${top_builddir}/src/tcs/libtcs.a  ${top_builddir}/src/tspi/libtspi.la -lgmp -lcrypto

# create a shared library for integrating daa_join and daa_sign operations with java code bindings generated with swig
lib_LTLIBRARIES = libtopographia_daa_join.la libtopographia_daa_sign.la

libtopographia_daa_join_la_SOURCES =daa_platform/topographia_daa_join.c daa_platform/topographia_daa_join_wrap.c daa_structs.c big_integer/bi_gmp.c big_integer/bi.c daa_debug.c utils/list.c daa_parameter.c ../obj_daa.c ../../include/tss/tspi.h
libtopographia_daa_join_la_CPPFLAGS =-fpic -I../../include/daa -I../../include -I../../include/tss -I/usr/lib/jvm/java-8-oracle/include -I/usr/lib/jvm/java-8-oracle/include/linux -DTSS_DEBUG -DBI_DEBUG -DAPPID=\"DAA_JOIN\" -DTSS_BUILD_DAA
libtopographia_daa_join_la_LIBADD =${top_builddir}/src/tcs/libtcs.a  -ltspi -lgmp -lcrypto
libtopographia_daa_join_LDFLAGS=-shared
libtopographia_daa_join_LDADD=${top_builddir}/src/tcs/libtcs.a  -ltspi -lgmp -lcrypto

test_sign_SOURCES = test_sign.c daa_structs.c big_integer/bi_gmp.c big_integer/bi.c daa_debug.c utils/list.c daa_parameter.c ../obj_daa.c ../../include/tss/tspi.h
test_sign_CFLAGS=-I../../include/daa -I../../include -I../../include/tss -DTSS_DEBUG -DBI_DEBUG -DAPPID=\"DAA_SIGN\" -DTSS_BUILD_DAA
test_sign_LDADD=${top_builddir}/src/tcs/libtcs.a  ${top_builddir}/src/tspi/libtspi.la -lgmp -lcrypto

libtopographia_daa_sign_la_SOURCES = topographia_daa_sign.c topographia_daa_sign_wrap.c daa_structs.c big_integer/bi_gmp.c big_integer/bi.c daa_debug.c utils/list.c daa_parameter.c ../obj_daa.c ../../include/tss/tspi.h
libtopographia_daa_sign_la_CPPFLAGS =-fpic -I../../include/daa -I../../include -I../../include/tss -I/usr/lib/jvm/java-8-oracle/include -I/usr/lib/jvm/java-8-oracle/include/linux -DTSS_DEBUG -DBI_DEBUG -DAPPID=\"DAA_SIGN\" -DTSS_BUILD_DAA
libtopographia_daa_sign_la_LIBADD =${top_builddir}/src/tcs/libtcs.a  -ltspi -lgmp -lcrypto
libtopographia_daa_sign_LDFLAGS=-shared
libtopographia_daa_sign_LDADD=${top_builddir}/src/tcs/libtcs.a  -ltspi -lgmp -lcrypto