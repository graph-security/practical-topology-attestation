%module topographia_daa_join
%include <typemaps.i>
%include <arrays_java.i>
%include <various.i>
//%apply signed char *INOUT {char *N_G};
%{
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
//#include <errno.h>
#include <openssl/err.h>
// for RSA Key
#include <openssl/rsa.h>
#include "../../../include/daa/daa_structs.h"
#include "trousers/tss.h"
#include "trousers/trousers.h"
//#include "spi_internal_types.h"
#include "../../../include/spi_utils.h"
#include "../../../include/obj.h"
#include "../../../include/tsplog.h"
#include "../../../include/daa/daa_parameter.h"
#include "../../../include/daa/verifier.h"
#include "../../../include/daa/platform.h"
#include "../../../include/daa/daa_debug.h"
#include "../../../include/obj_daa.h"
#include "../../../include/tss/tspi.h"
#include "../../../include/tss/tspi.h"
#include "../../../include/daa/bi.h"
#include "../../../include/daa/issuer.h"
#include "../../../include/daa/bi_gmp.h"
#include "../../../include/tcslog.h"

#define DEFAULT_FILENAME "issuer.txt"
#define DEFAULT_CREDENTIAL_FILENAME "credential.txt"
#define DEFAULT_DAACOUNTER 0x01020304
#define DEFAULT_OWN_PASSWD "OWN_PWD"

// from IssuerFactory
static const int DEFAULT_KEY_CHAIN_LENGTH = 3;

typedef struct tdIssuer {
    // use on Tspi calls
    TSS_DAA_PK *pk_extern;
    TSS_DAA_KEY_PAIR *key_pair_extern;

    // used internally
    int length_key_chain;
    RSA **key_chain;
    TSS_DAA_PK_internal *pk;
    DAA_PRIVATE_KEY_internal *private_key;
    TSS_DAA_PK_PROOF_internal *pk_proof;
    //RSA **auth_key_pairs;
    BYTE **pk_signatures;
    bi_ptr zeta;
} Issuer;


extern char *getNG(); 

extern void setNG(char *newNG); 

extern int tp_daa_join(int argc, char *argv[]) ;

%}


%typemap(jni) (int argc, char *argv[]) "jobjectArray"
%typemap(jtype) (int argc, char *argv[]) "String[]"
%typemap(jstype) (int argc, char *argv[]) "String[]"

%typemap(javain) (int argc, char *argv[]) "$javainput"

%typemap(in) (int argc, char *argv[]) (jstring *jsarray) {
int i;

  $1 = (*jenv)->GetArrayLength(jenv, $input);
  if ($1 == 0) {
    SWIG_JavaThrowException(jenv, SWIG_JavaIndexOutOfBoundsException, "Array must contain at least 1 element");
    return $null;
  }
  $2 = (char **) malloc(($1+1)*sizeof(char *));
  jsarray = (jstring *) malloc($1*sizeof(jstring));
  for (i = 0; i < $1; i++) {
    jsarray[i] = (jstring) (*jenv)->GetObjectArrayElement(jenv, $input, i);
    $2[i] = (char *) (*jenv)->GetStringUTFChars(jenv, jsarray[i], 0);
  }
  $2[i] = 0;
}

%typemap(argout) (int argc, char *argv[]) "" /* override char *[] default */

%typemap(freearg) (int argc, char *argv[]) {
int i;
  for (i = 0; i < $1; i++) {
    (*jenv)->ReleaseStringUTFChars(jenv, jsarray$argnum[i], $2[i]);
  }
  free($2);
}

%typemap(javaout) (char *BYTE) {
    return $jnicall;
}

%typemap(jni) const char *getNG "jobjectArray";
%typemap(jtype) const char *getNG "String[]";
%typemap(jstype) const char *getNG "String[]";
%typemap(javaout) const char *getNG {
  return $jnicall;
}
%typemap(out) const char *getNG {
  size_t count = 0;
  const char *pos = $1;
  while (*pos) {
    while (*pos++); // SKIP
    ++count;
  }
  $result = JCALL3(NewObjectArray, jenv, count, JCALL1(FindClass, jenv, "java/lang/String"), NULL);
  pos = $1;
  size_t idx = 0;
  while (*pos) {
    jobject str = JCALL1(NewStringUTF, jenv, pos);
    assert(idx<count);
    JCALL3(SetObjectArrayElement, jenv, $result, idx++, str);
    while (*pos++); // SKIP
  }
  //free($1); 
}


extern char *getNG(); 

extern void setNG(char *newNG); 

extern int tp_daa_join(int argc, char *argv[]);
