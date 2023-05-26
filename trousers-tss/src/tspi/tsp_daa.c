
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
#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "tcs_tsp.h"
#include "tspps.h"
#include "obj.h"
#include "obj_daa.h"

void
Trspi_LoadBlob_DAA_PK(UINT64 *offset, BYTE *blob, TSS_DAA_PK *pk)
{
	UINT32 i;

	Trspi_LoadBlob_TSS_VERSION(offset, blob, pk->versionInfo);

	Trspi_LoadBlob_UINT32(offset, pk->modulusLength, blob);
	Trspi_LoadBlob(offset, pk->modulusLength, blob, pk->modulus);

	Trspi_LoadBlob_UINT32(offset, pk->capitalSLength, blob);
	Trspi_LoadBlob(offset, pk->capitalSLength, blob, pk->capitalS);

	Trspi_LoadBlob_UINT32(offset, pk->capitalZLength, blob);
	Trspi_LoadBlob(offset, pk->capitalZLength, blob, pk->capitalZ);

	Trspi_LoadBlob_UINT32(offset, pk->capitalR0Length, blob);
	Trspi_LoadBlob(offset, pk->capitalR0Length, blob, pk->capitalR0);

	Trspi_LoadBlob_UINT32(offset, pk->capitalR1Length, blob);
	Trspi_LoadBlob(offset, pk->capitalR1Length, blob, pk->capitalR1);

	Trspi_LoadBlob_UINT32(offset, pk->gammaLength, blob);
	Trspi_LoadBlob(offset, pk->gammaLength, blob, pk->gamma);

	Trspi_LoadBlob_UINT32(offset, pk->capitalGammaLength, blob);
	Trspi_LoadBlob(offset, pk->capitalGammaLength, blob, pk->capitalGamma);

	Trspi_LoadBlob_UINT32(offset, pk->rhoLength, blob);
	Trspi_LoadBlob(offset, pk->rhoLength, blob, pk->rho);

	for (i = 0; i < pk->capitalYLength; i++)
		Trspi_LoadBlob(offset, pk->capitalYLength2, blob, pk->capitalY[i]);

	Trspi_LoadBlob_UINT32(offset, pk->capitalYPlatformLength, blob);

	Trspi_LoadBlob_UINT32(offset, pk->issuerBaseNameLength, blob);
	Trspi_LoadBlob(offset, pk->issuerBaseNameLength, blob, pk->issuerBaseName);
}

TSS_RESULT
Trspi_UnloadBlob_DAA_PK(UINT64 *offset, BYTE *blob, TSS_DAA_PK *pk)
{
	UINT32 i = 0, j;

	__tspi_memset(pk, 0, sizeof(TSS_DAA_PK));

	Trspi_UnloadBlob_TSS_VERSION(offset, blob, &pk->versionInfo);

	Trspi_UnloadBlob_UINT32(offset, &pk->modulusLength, blob);
	if (pk->modulusLength > 0) {
		if ((pk->modulus = malloc(pk->modulusLength)) == NULL)
			return TSPERR(TSS_E_OUTOFMEMORY);

		Trspi_UnloadBlob(offset, pk->modulusLength, blob, pk->modulus);
	} else {
		pk->modulus = NULL;
	}

	Trspi_UnloadBlob_UINT32(offset, &pk->capitalSLength, blob);
	if (pk->capitalSLength > 0) {
		if ((pk->capitalS = malloc(pk->capitalSLength)) == NULL)
			goto error;

		Trspi_UnloadBlob(offset, pk->capitalSLength, blob, pk->capitalS);
	} else {
		pk->capitalS = NULL;
	}

	Trspi_UnloadBlob_UINT32(offset, &pk->capitalZLength, blob);
	if (pk->capitalZLength > 0) {
		if ((pk->capitalZ = malloc(pk->capitalZLength)) == NULL)
			goto error;

		Trspi_UnloadBlob(offset, pk->capitalZLength, blob, pk->capitalZ);
	} else {
		pk->capitalZ = NULL;
	}

	Trspi_UnloadBlob_UINT32(offset, &pk->capitalR0Length, blob);
	if (pk->capitalR0Length > 0) {
		if ((pk->capitalR0 = malloc(pk->capitalR0Length)) == NULL)
			goto error;

		Trspi_UnloadBlob(offset, pk->capitalR0Length, blob, pk->capitalR0);
	} else {
		pk->capitalR0 = NULL;
	}

	Trspi_UnloadBlob_UINT32(offset, &pk->capitalR1Length, blob);
	if (pk->capitalR1Length > 0) {
		if ((pk->capitalR1 = malloc(pk->capitalR1Length)) == NULL)
			goto error;

		Trspi_UnloadBlob(offset, pk->capitalR1Length, blob, pk->capitalR1);
	} else {
		pk->capitalR1 = NULL;
	}

	Trspi_UnloadBlob_UINT32(offset, &pk->gammaLength, blob);
	if (pk->gammaLength > 0) {
		if ((pk->gamma = malloc(pk->gammaLength)) == NULL)
			goto error;

		Trspi_UnloadBlob(offset, pk->gammaLength, blob, pk->gamma);
	} else {
		pk->gamma = NULL;
	}

	Trspi_UnloadBlob_UINT32(offset, &pk->capitalGammaLength, blob);
	if (pk->capitalGammaLength > 0) {
		if ((pk->capitalGamma = malloc(pk->capitalGammaLength)) == NULL)
			goto error;

		Trspi_UnloadBlob(offset, pk->capitalGammaLength, blob, pk->capitalGamma);
	} else {
		pk->capitalGamma = NULL;
	}

	Trspi_UnloadBlob_UINT32(offset, &pk->rhoLength, blob);
	if (pk->rhoLength > 0) {
		if ((pk->rho = malloc(pk->rhoLength)) == NULL)
			goto error;

		Trspi_UnloadBlob(offset, pk->rhoLength, blob, pk->rho);
	} else {
		pk->rho = NULL;
	}

	Trspi_UnloadBlob_UINT32(offset, &pk->capitalYLength, blob);
	Trspi_UnloadBlob_UINT32(offset, &pk->capitalYLength2, blob);

	if (pk->capitalYLength > 0 && pk->capitalYLength2 > 0) {
		if ((pk->capitalY = calloc(pk->capitalYLength, sizeof(BYTE *))) == NULL)
			goto error;

		for (i = 0; i < pk->capitalYLength; i++) {
			if ((pk->capitalY[i] = malloc(pk->capitalYLength2)) == NULL)
				goto error;

			Trspi_UnloadBlob(offset, pk->capitalYLength2, blob, pk->capitalY[i]);
		}
	} else {
		pk->capitalY = NULL;
	}

	Trspi_UnloadBlob_UINT32(offset, &pk->capitalYPlatformLength, blob);

	Trspi_UnloadBlob_UINT32(offset, &pk->issuerBaseNameLength, blob);
	if (pk->issuerBaseNameLength > 0) {
		if ((pk->issuerBaseName = malloc(pk->issuerBaseNameLength)) == NULL)
			goto error;

		Trspi_UnloadBlob(offset, pk->issuerBaseNameLength, blob, pk->issuerBaseName);
	} else {
		pk->issuerBaseName = NULL;
	}

	return TSS_SUCCESS;

error:
	free(pk->modulus);
	free(pk->capitalS);
	free(pk->capitalZ);
	free(pk->capitalR0);
	free(pk->capitalR1);
	free(pk->gamma);
	free(pk->capitalGamma);
	free(pk->rho);
	if (pk->capitalY) {
		for (j = 0; j < i; j++)
			free(pk->capitalY[j]);

		free(pk->capitalY);
	}
	free(pk->issuerBaseName);

	__tspi_memset(pk, 0, sizeof(TSS_DAA_PK));

	return TSPERR(TSS_E_OUTOFMEMORY);
}

TSS_RESULT
Tcsip_TPM_DAA_Join(TCS_CONTEXT_HANDLE tcsContext, // in
			TSS_HDAA hDAA, // in
			BYTE stage, // in
			UINT32 inputSize0, // in
			BYTE* inputData0, // in
			UINT32 inputSize1, // in
			BYTE* inputData1, // in
			TPM_AUTH* ownerAuth, // in/out
			UINT32* outputSize, // out
			BYTE** outputData // out
) {
	TSS_RESULT result;
	TSS_HPOLICY hPolicy;
	TCPA_DIGEST digest;
	UINT64 offset = 0;
	BYTE hashblob[10000];
    Trspi_HashCtx hashCtx;

	TPM_HANDLE hTPM;
	TPM_HANDLE join_session;
    LogDebug("enter tsp_daa.c");

	// TPM_HANDLE hTPM;
	if( (result = obj_daa_get_handle_tpm( hDAA, &hTPM)) != TSS_SUCCESS)
		return result;
	if( (result = obj_daa_get_session_handle( hDAA, &join_session)) != TSS_SUCCESS)
		return result;
	LogDebug("Tcsip_TPM_DAA_Join(tcsContext=%x,hDAA=%x,join_session=%x, hTPM=%x stage=%d)",
		tcsContext,
		hDAA,
		join_session,
		hTPM,
		stage);

	LogDebug("obj_tpm_get_policy(hTPM=%X)", hTPM);

	if( (result = obj_tpm_get_policy( hTPM, TSS_POLICY_USAGE, &hPolicy)) != TSS_SUCCESS)
		return result;

    // Authorization Digest calculation
    result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
    result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_DAA_Join);
    result |= Trspi_Hash_BYTE(&hashCtx, stage);
    result |= Trspi_Hash_UINT32(&hashCtx, inputSize0);
    result |= Trspi_HashUpdate(&hashCtx,inputSize0,  inputData0);
    result |= Trspi_Hash_UINT32(&hashCtx, inputSize1);
    result |= Trspi_HashUpdate(&hashCtx, inputSize1, inputData1);
    if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
        return result;

//    LogDebug("digest :%x ", Decode_UINT32(digest.digest));

	if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_DAA_Join,
	     hPolicy, FALSE, &digest,
	     ownerAuth)) != TSS_SUCCESS) return result;

//	LogDebug("secret_PerformAuth_OIAP(hTPM, TPM_ORD_DAA_Join ret=%d", result);

//	LogDebug("TCSP_DAAJoin(tcsContext=%x,hTPM=%x,STAGE=%x,inputSize0=%x,inputData0=%x,inputSize1=%x,inputData1=%x,ownerAuthData=%x)\n",
//		tcsContext,
//		hTPM,
//		stage,
//		inputSize0,
//             Decode_UINT32(inputData0),
//		inputSize1,
//             Decode_UINT32(inputData1),
//             Decode_UINT32(ownerAuth->HMAC.authdata));
	/* step of the following call:
	TCSP_DAAJoin 		tcsd_api/calltcsapi.c (define in spi_utils.h)
	TCSP_DAAJoin_TP 	tcsd_api/tcstp.c (define in	trctp.h)
	*/
//	result =  0;

//            if ((stage== (BYTE) 1) || (stage==(BYTE) 2) || (stage==(BYTE) 3) ) {
            if (stage>0) {
              hTPM = join_session;
//              LogDebug("hTpm is now %x", hTPM);
            }

            result = TCS_API(tcsContext)->DaaJoin(
                tcsContext,
                hTPM,
                stage,
                inputSize0, inputData0,
                inputSize1, inputData1,
                ownerAuth,
                outputSize, outputData
            );
//        }

//        TCSP_DaaJoin_internal( tcsContext,
//				hTPM,
//				stage,
//				inputSize0, inputData0,
//				inputSize1, inputData1,
//				ownerAuth,
//				outputSize, outputData);
	if( result != TSS_SUCCESS) return result;


    result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
    result |= Trspi_Hash_UINT32(&hashCtx, TPM_SUCCESS);
    result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_DAA_Join);
    result |= Trspi_Hash_UINT32(&hashCtx, *outputSize);
    result |= Trspi_HashUpdate(&hashCtx,*outputSize,  *outputData);
    if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
        return result;

    LogDebug("TCSP_DAAJoin stage=%d outputSize=%d outputData=%x RESULT=%d",
             (int)stage, (int)*outputSize, (int)outputData, (int)result);

	if( (result = obj_policy_validate_auth_oiap( hPolicy, &digest, ownerAuth))) {
		LogError("obj_policy_validate_auth=%d", result);
	}

	return result;
}

TSS_RESULT Tcsip_TPM_DAA_Sign( TCS_CONTEXT_HANDLE hContext,	// in
                               TPM_HANDLE handle,	// in
                               BYTE stage,	// in
                               UINT32 inputSize0,	// in
                               BYTE* inputData0,	// in
                               UINT32 inputSize1,	// in
                               BYTE* inputData1,	// in
                               TPM_AUTH* ownerAuth,	// in, out
                               UINT32* outputSize,	// out
                               BYTE** outputData	// out
) {
    TSS_RESULT result;
    TSS_HPOLICY hPolicy;
    TCPA_DIGEST digest;
    UINT16 offset = 0;
    BYTE hashblob[1000];
    TPM_HANDLE hTPM;
    TPM_HANDLE session_handle;
    TSS_HDAA hDAA = (TSS_HDAA)handle;
    Trspi_HashCtx hashCtx;

    if( (result = obj_daa_get_handle_tpm( hDAA, &hTPM)) != TSS_SUCCESS)
        return result;
    if( (result = obj_daa_get_session_handle( hDAA, &session_handle)) != TSS_SUCCESS)
        return result;
    LogDebug("Tcsip_TPM_DAA_Sign(tcsContext=%x,hDAA=%x,sign_session=%x, hTPM=%x stage=%d)",
             hContext,
             hDAA,
             session_handle,
             hTPM,
             stage);

//    LogDebug("obj_tpm_get_policy(hTPM=%X)", hTPM);

    if( (result = obj_tpm_get_policy( hTPM, TSS_POLICY_USAGE,  &hPolicy)) != TSS_SUCCESS)
        return result;

    result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
    result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_DAA_Sign);
    result |= Trspi_Hash_BYTE(&hashCtx, stage);
    result |= Trspi_Hash_UINT32(&hashCtx, inputSize0);
    result |= Trspi_HashUpdate(&hashCtx,inputSize0,  inputData0);
    result |= Trspi_Hash_UINT32(&hashCtx, inputSize1);
    result |= Trspi_HashUpdate(&hashCtx, inputSize1, inputData1);
    if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
        return result;

    if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_DAA_Sign,
                                          hPolicy,FALSE, &digest,
                                          ownerAuth)) != TSS_SUCCESS) return result;
//    LogDebug("secret_PerformAuth_OIAP(hTPM, TPM_ORD_DAA_Sign ret=%d", result);
/*    LogDebug("TCSP_DAASign(%x,%x,stage=%x,%x,%x,%x,%x,%x)",
             hContext,
             hTPM,
             stage,
             inputSize0,(int)inputData0,
             inputSize1,(int)inputData1,
             (int)&ownerAuth);
*/
    /* step of the following call:
    TCSP_DAASign 		tcsd_api/calltcsapi.c (define in spi_utils.h)
    TCSP_DAASign_TP 	tcsd_api/tcstp.c (define in	trctp.h)
    */


    if (stage>0) {
        hTPM = session_handle;
//        LogDebug("hTpm is now %x", hTPM);
    }
    result =  TCS_API(hContext)->DaaSign(
        hContext,
//        session_handle,
        hTPM,
        stage,
        inputSize0, inputData0,
        inputSize1, inputData1,
        ownerAuth,
        outputSize, outputData
    );

//        TCSP_DaaSign_internal( hContext,
//				session_handle,
//				stage,
//				inputSize0, inputData0,
//				inputSize1, inputData1,
//				ownerAuth,
//				outputSize, outputData);
    if( result != TSS_SUCCESS) return result;


    result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
    result |= Trspi_Hash_UINT32(&hashCtx, TPM_SUCCESS);
    result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_DAA_Sign);
    result |= Trspi_Hash_UINT32(&hashCtx, *outputSize);
    result |= Trspi_HashUpdate(&hashCtx,*outputSize,  *outputData);
    if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
        return result;

    LogDebug("TCSP_DAASign stage=%d outputSize=%d outputData=%x RESULT=%d",
             (int)stage, (int)*outputSize, (int)outputData, (int)result);

    if( (result = obj_policy_validate_auth_oiap( hPolicy, &digest, ownerAuth)))
    {
        LogError("obj_policy_validate_auth=%d", result);
    }

    return result;
}
