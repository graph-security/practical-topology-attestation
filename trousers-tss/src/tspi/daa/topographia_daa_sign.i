%module topographia_daa_sign
%include <typemaps.i>
%include <arrays_java.i>
%include <various.i>
%{
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include "daa_structs.h"
#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_utils.h"
#include "obj.h"
#include "tsplog.h"
#include "daa_parameter.h"
#include "verifier.h"
#include "platform.h"
#include "../../include/tss/tspi.h"
#include "daa_debug.h"
#include "../../include/daa/bi.h"
#include "../../include/tcslog.h"
#include "../../include/obj_daa.h"
#include "../../include/daa/daa_parameter.h"
#include "../../include/daa/daa_structs.h"
#include "../../include/daa/bi_gmp.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>

#define DEFAULT_CREDENTIAL_FILENAME "credential.txt"
#define DEFAULT_SIGNATURE_FILENAME "signature.txt"
#define DEFAULT_SIGN_DATA_FILENAME "sign-data.txt"
#define DEFAULT_OWN_PASSWD "OWN_PWD"

static char *isSignatureCorrect = "no";

extern char *getSignResult();
extern void setSignResult(char *result);

extern int tp_daa_sign(int argc, char *argv[]) ;
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

%typemap(jni) const char *getSignResult "jobjectArray";
%typemap(jtype) const char *getSignResult "String[]";
%typemap(jstype) const char *getSignResult "String[]";
%typemap(javaout) const char *getSignResult {
  return $jnicall;
}
%typemap(out) const char *getSignResult {
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

extern char *getSignResult();

extern void setSignResult(char *result);

extern int tp_daa_sign(int argc, char *argv[]);
