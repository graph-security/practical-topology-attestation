
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2006
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// for message digest
#include <openssl/evp.h>

#include <stdlib.h>
#include "daa/daa_structs.h"
#include "daa/daa_parameter.h"
#include "trousers/tss.h"
//#include "spi_internal_types.h"
#include "spi_utils.h"
#include <trousers/trousers.h>
#include <spi_utils.h>
#include <obj.h>
#include "tsplog.h"
#include "tss/tcs.h"
#include "obj_daa.h"

/*
Verifies if the key is a valid endorsement key of a TPM. (TPM is good)
return 0 if correct
 */
int verify_ek_and_daaCounter(
	UINT32 endorsementLength,
	BYTE *endorsementCredential,
	UINT32 daaCounter
) {
	// TODO
	return 0;
}


TSPICALL Tspi_DAA_IssueInit_internal(
	TSS_HDAA	hDAA,	// in
    RSA*	issuerAuthPK,	// in
    TSS_DAA_KEY_PAIR	issuerKeyPair,	// in (TSS_DAA_KEY_PAIR *)
	TSS_DAA_IDENTITY_PROOF	*identityProof,	// in
	UINT32	capitalUprimeLength,	// in
	BYTE*	capitalUprime,	// in
	UINT32	daaCounter,	// in
	UINT32*	nonceIssuerLength,	// out
	BYTE**	nonceIssuer,	// out
	UINT32*	authenticationChallengeLength,	// out
	BYTE**	authenticationChallenge,	// out
	TSS_DAA_JOIN_ISSUER_SESSION*	joinSession	// out
) {
	TCS_CONTEXT_HANDLE tcsContext;
	TSS_RESULT result;
	BYTE *ne, *buffer, **authChallenge = NULL;
	bi_t random;
	int length_ne;

    LogDebug("enter issuer init");

	if( (result = obj_daa_get_tsp_context( hDAA, &tcsContext)) != TSS_SUCCESS)
		return result;
	// 1 & 2 : verify EK (and associated credentials) of the platform
	if( verify_ek_and_daaCounter( identityProof->endorsementLength,
				identityProof->endorsementCredential, daaCounter) != 0) {
		LogError("EK verification failed");
		return TSS_E_INTERNAL_ERROR;
	}

	// 3 : choose a random nonce for the platform (ni)
	bi_new( random);
    bi_urandom( random, DAA_PARAM_LENGTH_MESSAGE_DIGEST * 8);
    LogDebug("issuer randomness: %s",  bi_2_hex_char(random));

	buffer = bi_2_nbin(nonceIssuerLength, random);
	if( buffer == NULL) {
		LogError("malloc of %d bytes failed", *nonceIssuerLength);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

//	*nonceIssuer =  convert_alloc( tcsContext, *nonceIssuerLength, buffer);
    LogDebug("issuer randomness buffer: %s",  dump_byte_array(20, buffer));

    BYTE *ni = convert_alloc(tcsContext, 20, buffer);
	if (*ni == NULL) {
		LogError("malloc of %d bytes failed", *nonceIssuerLength);
		free( buffer);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

    nonceIssuer = &ni;

	LogDebug("nonce Issuer[%d:%d]:%s", DAA_PARAM_LENGTH_MESSAGE_DIGEST,
		*nonceIssuerLength,
		dump_byte_array( 20 , *nonceIssuer));

	// 4 : choose a random nonce ne and encrypt it under EK
	bi_urandom( random, DAA_PARAM_LENGTH_MESSAGE_DIGEST * 8);
	ne = convert_alloc( tcsContext, length_ne, bi_2_nbin( &length_ne, random));
	if (ne == NULL) {
		LogError("malloc of %d bytes failed", length_ne);
		free( buffer);
		free( nonceIssuer);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}

	bi_free( random);
	*authenticationChallenge = (BYTE *)calloc_tspi( tcsContext, 256); // 256: RSA size
	if (*authenticationChallenge == NULL) {
		LogError("malloc of %d bytes failed", 256);
		free( buffer);
		free( nonceIssuer);
		free( ne);
		return TSPERR(TSS_E_OUTOFMEMORY);
	}
    LogDebug("endorsement key=%s", dump_byte_array( identityProof->endorsementLength, identityProof->endorsementCredential));

    result = Trspi_RSA_Encrypt(
		ne,	// message to encrypt
		length_ne,	// length message to encrypt
		*authenticationChallenge,	// destination
		authenticationChallengeLength, // length destination
		identityProof->endorsementCredential, // public key
		identityProof->endorsementLength); // public key size

	if( result != TSS_SUCCESS) {
		LogError("Can not encrypt the Authentication Challenge");
		free( buffer);
		free( nonceIssuer);
		free( ne);
		return TSS_E_INTERNAL_ERROR;
	}
	LogDebug("authenticationChallenge[%d:%d]:%s", DAA_PARAM_LENGTH_MESSAGE_DIGEST,
		*authenticationChallengeLength,
		dump_byte_array( *authenticationChallengeLength , *authenticationChallenge));

	// 5 : save PK, PKDAA, (p', q'), U', daaCounter, ni, ne in joinSession
	// EK is not a member of joinSession but is already saved in identityProof
	joinSession->issuerAuthPK =  issuerAuthPK;
	joinSession->issuerKeyPair = issuerKeyPair; 
	joinSession->identityProof= *identityProof;
	joinSession->capitalUprimeLength = capitalUprimeLength;
	joinSession->capitalUprime = capitalUprime;
	joinSession->daaCounter = daaCounter;
	joinSession->nonceIssuerLength = *nonceIssuerLength;
	joinSession->nonceIssuer = *nonceIssuer;
	joinSession->nonceEncryptedLength = length_ne;
	joinSession->nonceEncrypted = ne;
	return result;
}
