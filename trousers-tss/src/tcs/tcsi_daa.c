
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcsps.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "req_mgr.h"
#include "tcsd_wrap.h"
#include "tcsd.h"


TSS_RESULT
TCSP_DaaJoin_internal(TCS_CONTEXT_HANDLE hContext, /* in */
		      TPM_HANDLE handle, /* in */
		      BYTE stage,               /* in */
		      UINT32 inputSize0,   /* in */
		      BYTE *inputData0,   /* in */
		      UINT32 inputSize1, /* in */
		      BYTE *inputData1, /* in */
		      TPM_AUTH * ownerAuth,	/* in, out */
		      UINT32 *outputSize, /* out */
		      BYTE **outputData)  /* out */
{
	UINT64 offset = 0;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];
    TPM_AUTH **auth2 = NULL;

	LogDebugFn("Enter TCSP_DaaJoin_internal");
	if ( (result = ctx_verify_context(hContext)) != TSS_SUCCESS)
		return result;
	if( (result = auth_mgr_check(hContext, &ownerAuth->AuthHandle)) != TSS_SUCCESS)
		goto done;

	if ((result = tpm_rqu_build(TPM_ORD_DAA_Join, &offset, txBlob, handle, stage, inputSize0, inputData0, inputSize1, inputData1, ownerAuth)))
		goto done;

	LogDebug("req_mgr_submit_req  (oldOffset=%" PRIu64 ")", offset);
	if ((result = req_mgr_submit_req(txBlob)))
		goto done;

    result = UnloadBlob_Header(txBlob, &paramSize);
	if (!result) {
        auth2 = &ownerAuth;
        result = tpm_rsp_parse(TPM_ORD_DAA_Join, txBlob, paramSize, outputSize, outputData, auth2);
	}

    LogDebug("UnloadBlob  (paramSize=%d) result=%d", paramSize, result);
    LogDebug("-->> join stage %d", (int) stage);
done:
    LogDebug("ownerAuth nonceOdd: %x ", Decode_UINT32(ownerAuth->NonceOdd.nonce));
    LogDebug("ownerAuth nonceEven: %x ", Decode_UINT32(ownerAuth->NonceEven.nonce));
    LogDebug("ownerAuth authdata: %x ", Decode_UINT32(ownerAuth->HMAC.authdata));
    LogDebug("ownerAuth auth handle : %x ", ownerAuth->AuthHandle);
	LogDebug("Leaving DaaJoin with result:%d", result);
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;
}

TSS_RESULT TCSP_DaaSign_internal(TCS_CONTEXT_HANDLE hContext, /* in */
				 TPM_HANDLE handle, /* in */
				 BYTE stage,               /* in */
				 UINT32 inputSize0,   /* in */
				 BYTE *inputData0,   /* in */
				 UINT32 inputSize1, /* in */
				 BYTE *inputData1, /* in */
				 TPM_AUTH * ownerAuth,	/* in, out */
				 UINT32 *outputSize, /* out */
				 BYTE **outputData)  /* out */
{
	UINT64 offset = 0;
	UINT32 paramSize;
	TSS_RESULT result;
	BYTE txBlob[TSS_TPM_TXBLOB_SIZE];
    TPM_AUTH **auth2 = NULL;

	LogDebugFn("Enter TCSP_DaaSign_internal");
	if ( (result = ctx_verify_context(hContext)) != TSS_SUCCESS)
		return result;

	if( (result = auth_mgr_check(hContext, &ownerAuth->AuthHandle)) != TSS_SUCCESS)
		goto done;

	if ((result = tpm_rqu_build(TPM_ORD_DAA_Sign, &offset, txBlob, handle, stage, inputSize0,
				    inputData0, inputSize1, inputData1, ownerAuth)))
		goto done;

	LogDebug("req_mgr_submit_req  (oldOffset=%" PRIu64 ")", offset);
	if ((result = req_mgr_submit_req(txBlob))) goto done;

	result = UnloadBlob_Header(txBlob, &paramSize);

    if (!result) {
        auth2 = &ownerAuth;
        result = tpm_rsp_parse(TPM_ORD_DAA_Sign, txBlob, paramSize, outputSize, outputData, auth2);
	}

done:
	auth_mgr_release_auth(ownerAuth, NULL, hContext);
	return result;
}

