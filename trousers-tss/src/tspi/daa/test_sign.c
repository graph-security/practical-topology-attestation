
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2006
 *
 */

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

// for RSA Key
#include <openssl/rsa.h>
#include <openssl/evp.h>

#define DEFAULT_CREDENTIAL_FILENAME "credential.txt"
#define DEFAULT_SIGNATURE_FILENAME "signature.txt"
#define DEFAULT_SIGN_DATA_FILENAME "sign-data.txt"
#define DEFAULT_OWN_PASSWD "OWN_PWD"

int print_usage(char  *exec) {
	fprintf(stderr, "usage: %s\n", exec);
	fprintf(stderr,
		"\t-m,\t--message\n\t\tif define, the data is signed using this message\n\
\t\totherwise an AIK will be generated and used\n");
	fprintf(stderr,
		"\t-pw,\t--passwd\n\t\ttpm owner password (default: %s)\n",
		DEFAULT_OWN_PASSWD);
	fprintf(stderr,
		"\t-cr,\t--credential\n\t\tcredential filename (default: %s)\n",
		DEFAULT_CREDENTIAL_FILENAME);
	return -1;
}

int main(int argc, char *argv[]) {
	TSS_HCONTEXT hContext;
	TSS_RESULT result;
	TSS_HTPM hTPM;
	TSS_HPOLICY hPolicy;
	char *credential_filename = DEFAULT_CREDENTIAL_FILENAME;
    char *signature_filename = DEFAULT_SIGNATURE_FILENAME;
    char *signData_filename = DEFAULT_SIGN_DATA_FILENAME;
	UINT32 nonceVerifierLength;
	BYTE *nonceVerifier;
	TSS_HDAA hDAA;
	TSS_DAA_CREDENTIAL hDaaCredential;
	TSS_DAA_SIGN_DATA signData;
	TSS_DAA_SIGNATURE daaSignature;
	TSS_DAA_SELECTED_ATTRIB revealAttributes;
	char *szTpmPasswd = DEFAULT_OWN_PASSWD;
	char *message = NULL;
	BYTE **attributes = NULL;
	FILE *file;
	char *param;
	int i, length, rv;
	bi_ptr random = NULL;
	TSS_BOOL isCorrect;
	EVP_MD_CTX *mdctx;
	TSS_HKEY hKEY;
    UINT32 verifierBaseNameLength;
    char *verifierBaseName;

    FILE *csvFile;
    struct timeval begin, end;
    time_t rawtime;
    struct tm *info;
    char bf[80];

	init_tss_version( &signData);
	init_tss_version( &daaSignature);
	init_tss_version( &revealAttributes);

	i = 1;
	while( i < argc) {
		param = argv[ i];
		if ( strcmp( param, "-m") == 0 || strcmp( param, "--message") == 0) {
			i++;
			if( i == argc) return print_usage( argv[0]);
			message = argv[i];
		} else if( strcmp( param, "-cr") == 0 || strcmp( param, "--credential") == 0){
			i++;
			if( i == argc) return print_usage( argv[0]);
			credential_filename = argv[i];
		} else if( strcmp( param, "-pw") == 0 || strcmp( param, "--passwd") == 0){
			i++;
			if( i == argc) return print_usage( argv[0]);
			szTpmPasswd = argv[i];
		} else {
			fprintf(stderr, "%s:unrecognized option `%s'\n", argv[0], param);
			return print_usage( argv[0]);
		}
		i++;
	}
	bi_init( NULL);
	printf("Loading credential: %s ", credential_filename);
	file = fopen( credential_filename, "r");
    hDaaCredential = *load_TSS_DAA_CREDENTIAL(file);
//	if( (hDaaCredential =  *load_TSS_DAA_CREDENTIAL(file)) == 0) {
// TODO fix if for daa credential
    if (hDaaCredential.capitalALength==0) {
		LogError( "[test_join]: Error when loading \'%s\': %s\n",
			credential_filename,
			strerror( errno));
		result = TSS_E_FAIL;
		goto out_close;
	}
	fclose( file);
	printf("Done\n");

	// Create Context
	LogDebug("Create Context");
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		LogError( "Tspi_Context_Create %d\n", result );
		goto out;
	}
	// Connect to Context
	result = Tspi_Context_Connect( hContext, NULL );
	if ( result != TSS_SUCCESS) goto out_close;
	printf("\nConnect to the context: %X\n", hContext);

	if( (result = Tspi_Context_GetTpmObject( hContext, &hTPM)) != TSS_SUCCESS)
		goto out_close;
	// Get the correct policy using the TPM ownership PASSWD
	if( (result = Tspi_GetPolicyObject( hTPM, TSS_POLICY_USAGE, &hPolicy)) != TSS_SUCCESS)
		goto out_close;
	if( (result = Tspi_Policy_SetSecret( hPolicy,
						TSS_SECRET_MODE_PLAIN,
						strlen( szTpmPasswd),
						szTpmPasswd)) != TSS_SUCCESS)
		goto out_close;
	LogDebug("Tspi_Policy_SetSecret hPolicy received;%d", hPolicy);

	//Create Object
	result = obj_daa_add( hContext, &hDAA);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Context_CreateObject:%d", result);
		Tspi_Context_Close(hContext);
		LogError("%s: %s", argv[0], err_string(result));
		exit(result);
	}
	LogDebug("created DAA object:%X", hDAA);

	// TODO: verifier base name
	result = Tspi_DAA_VerifyInit(
		hDAA,	// in
		&nonceVerifierLength,	// out
		&nonceVerifier,	// out
		0, //baseNameLength,	// out
		NULL //baseName		// out
	);
	if (result != TSS_SUCCESS) goto out_close;
	LogDebug("Verify Init return nonceVerifier [%s]",
			dump_byte_array( nonceVerifierLength, nonceVerifier));

	create_TSS_DAA_SELECTED_ATTRIB( &revealAttributes, 5, 0, 1, 1, 0, 0);

	mdctx = EVP_MD_CTX_create();

    message = "hello";
	// create the TSS_DAA_SIGN_DATA struct
	// .selector: 0 -> payload contains a handle to an AIK
	//            1 -> payload contains a hashed message
	if( message != NULL) {
		signData.selector = TSS_FLAG_DAA_SIGN_MESSAGE_HASH;
		signData.payloadFlag = TSS_FLAG_DAA_SIGN_MESSAGE_HASH;
		EVP_DigestInit(mdctx, DAA_PARAM_get_message_digest());
		EVP_DigestUpdate(mdctx,  (BYTE *)message, strlen( message));
		signData.payloadLength = EVP_MD_CTX_size(mdctx);
		signData.payload = (BYTE *)EVP_MD_CTX_create();
		EVP_DigestFinal(mdctx, signData.payload, NULL);
	} else {
		signData.selector = TSS_FLAG_DAA_SIGN_IDENTITY_KEY;
		result = Tspi_Context_CreateObject(
			hContext,	 //  in
			TSS_OBJECT_TYPE_RSAKEY,		//  in
			TSS_KEY_SIZE_2048,		//  in
			&hKEY	//  out
		);
		if( result != TSS_SUCCESS) goto out_close;

	}

    verifierBaseNameLength = 15;
    verifierBaseName = "topographia-123";

    // start measuring time
        gettimeofday(&begin, 0);

	result = Tspi_TPM_DAA_Sign(
		hDAA,	// in
		hTPM,	// in
		hDaaCredential,	// in
		&revealAttributes,	// in
		verifierBaseNameLength, // verifierBaseNameLength,	// in
        (BYTE *) verifierBaseName, // verifierBaseName,	// in
		nonceVerifierLength,	// in
		nonceVerifier,	// in
		&signData,	// in
        (TSS_DAA_SIGNATURE **) &daaSignature    // out
	);
	if (result != TSS_SUCCESS) goto out_close;

	// stop measuring time and compute the elapsed time
	gettimeofday(&end, 0);
	long seconds = end.tv_sec - begin.tv_sec;
	long microseconds = end.tv_usec - begin.tv_usec;
	double elapsed = seconds + microseconds*1e-6;
        printf("Time measured: %.3f seconds.\n", elapsed);

        csvFile = fopen("daa_sign.csv", "a");
	fprintf(csvFile, "%.3f\n", elapsed);
	fclose(csvFile);

	LogDebug("TPM_DAA_Sign return daaSignature [%s]",
			dump_byte_array( nonceVerifierLength, nonceVerifier));


    printf("Saving signature: %s \n ", signature_filename);
	file = fopen( signature_filename, "w");

	if( save_TSS_DAA_SIGNATURE(file, (TSS_DAA_SIGNATURE *) &daaSignature) != 0) {
		LogError( "[test_sign]: Error when saving \'%s\': %s",
			signature_filename,
			strerror( errno));
		result = TSS_E_FAIL;
		goto out_close;
	}
	fclose(file);
	printf("Done saving signature file\n");

    printf("Saving sign data: %s \n ", signData_filename);
    file = fopen( signData_filename, "w");

    if( save_TSS_DAA_SIGN_DATA(file, (TSS_DAA_SIGN_DATA *) &signData) != 0) {
        LogError( "[test_sign]: Error when saving \'%s\': %s",
                  signData_filename,
                  strerror( errno));
        result = TSS_E_FAIL;
        goto out_close;
    }
    fclose(file);
    printf("Done saving sign data file\n");

// TODO enable attributes
	// generate attributes list but without copying the not revealed ones
//	attributes = malloc( sizeof(BYTE *) * hDaaCredential->attributesLength);
//	for( i=0; i < (int)(hDaaCredential->attributesLength); i++) {
//		if( revealAttributes.indicesList[i]) {
//			attributes[i] = (BYTE *)malloc( DAA_PARAM_SIZE_F_I / 8);
//			memcpy( attributes[i],
//				hDaaCredential->attributes[i],
//				DAA_PARAM_SIZE_F_I / 8);
//		} else {
//			attributes[i] = NULL;
//		}
//	}

    	// start time
    	gettimeofday(&begin, 0);
	result = Tspi_DAA_VerifySignature(
		hDAA,	// in
		&daaSignature,	// in
		hDaaCredential.issuerPK,	// in
		&signData,	// in
		hDaaCredential.attributesLength,	// in
		attributes,	// in
		nonceVerifierLength,	// in
		nonceVerifier,	// in
        verifierBaseNameLength, // verifierBaseNameLength,	// in
        (BYTE *) verifierBaseName, // verifierBaseName,	// in
		&isCorrect	// out
	);

	// stop measuring time and compute the elapsed time
	gettimeofday(&end, 0);
	seconds = end.tv_sec - begin.tv_sec;
	microseconds = end.tv_usec - begin.tv_usec;
	elapsed = seconds + microseconds*1e-6;
        printf("Time measured: %.3f seconds.\n", elapsed);

        csvFile = fopen("daa_verify_signature.csv", "a");
	fprintf(csvFile, "%.3f\n", elapsed);
	fclose(csvFile);
	printf(">>>>>> Signature correct:%s\n", ( isCorrect ? "yes" : "no"));

out_close:
	EVP_MD_CTX_destroy(mdctx);
	if( attributes != NULL) {
		for( i=0; i<(int)hDaaCredential.attributesLength; i++) {
			if( attributes[i] != NULL) free( attributes[i]);
		}
		free( attributes);
	}
	if( random != NULL) bi_free_ptr( random);
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
out:
	bi_release();
	LogDebug("THE END result=%d:%s",result, err_string( result) );;
	return result;
}

