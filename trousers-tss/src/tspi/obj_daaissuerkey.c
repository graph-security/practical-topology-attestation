
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2006, 2007
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"
#include "obj_daa.h"

struct obj_list daaissuerkey_list;

/*
 * adds a new daa object to the daa list with TSP context tspContext
 */
TSS_RESULT
obj_daaissuerkey_add(TSS_HCONTEXT tspContext, TSS_HOBJECT *phObject)
{
    TSS_RESULT result;
    struct tr_daa_obj *daa = calloc(1, sizeof(struct tr_daa_obj));

    if (daa == NULL) {
        LogError("malloc of %d bytes failed.", sizeof(struct tr_daa_obj));
        return TSPERR(TSS_E_OUTOFMEMORY);
    }

    if ((result = obj_list_add(&daaissuerkey_list, tspContext, 0, daa, phObject))) {
        free(daa);
        return result;
    }
    printf("daaarakey add method");
    return TSS_SUCCESS;
}


void
daaissuerkey_free(void *data)
{
    struct tr_daa_obj *daa = (struct tr_daa_obj *)data;

    /* free all pointers in the tr_daa_obj object here */
    free(daa);
}

/*
 * remove DAA object hObject from the DAA list
 */
TSS_RESULT
obj_daaissuerkey_remove(TSS_HOBJECT hObject, TSS_HCONTEXT tspContext)
{
    TSS_RESULT result;

    if ((result = obj_list_remove(&daaissuerkey_list, &daa_free, hObject, tspContext)))
        return result;

    return TSS_SUCCESS;
}

TSS_BOOL
obj_is_daaissuerkey(TSS_HOBJECT hObject)
{
    TSS_BOOL answer = FALSE;

    if ((obj_list_get_obj(&daaissuerkey_list, hObject))) {
        answer = TRUE;
        obj_list_put(&daaissuerkey_list);
    }

    return answer;
}

TSS_RESULT
obj_daaissuerkey_get_tsp_context(TSS_HDAA hDaa, TSS_HCONTEXT *tspContext)
{
    struct tsp_object *obj;

    if ((obj = obj_list_get_obj(&daaissuerkey_list, hDaa)) == NULL)
        return TSPERR(TSS_E_INVALID_HANDLE);

    *tspContext = obj->tspContext;

    obj_list_put(&daaissuerkey_list);

    return TSS_SUCCESS;
}

TSS_RESULT
obj_daaissuerkey_set_daa_handle(TSS_HDAA_ISSUER_KEY key, TPM_HANDLE handle) {
    LogDebug("set daa handle");

    return TSS_SUCCESS;
}

TSS_RESULT obj_daaissuerkey_get_capitalSprime(TSS_HDAA_ISSUER_KEY key,
                                              UINT32 *pInt,
                                              BYTE **pString) {
    LogDebug("get capitalSprime");
    return TSS_SUCCESS;

}
TSS_RESULT obj_daaissuerkey_get_daa_issuer(TSS_HDAA_ISSUER_KEY key,
                                           const int *pInt,
                                           BYTE **pString){
    LogDebug("get daa issuer");
    return TSS_SUCCESS;
}

TSS_RESULT obj_daaissuerkey_get_modulus(TSS_HDAA_ISSUER_KEY key,
                                        UINT32 *pInt,
                                        BYTE **pString){
    LogDebug("get modulus");
    return TSS_SUCCESS;
}
TSS_RESULT obj_daaissuerkey_get_capitalR1(TSS_HDAA_ISSUER_KEY key,
                                          UINT32 *pInt,
                                          BYTE **pString){
    LogDebug("get capital R1");
    return TSS_SUCCESS;
}
TSS_RESULT obj_daaissuerkey_get_capitalS(TSS_HDAA_ISSUER_KEY key,
                                         UINT32 *pInt,
                                         BYTE **pString){
    LogDebug("get capitalS");
    return TSS_SUCCESS;
}
TSS_RESULT obj_daaissuerkey_get_capitalR0(TSS_HDAA_ISSUER_KEY key,
                                          UINT32 *pInt,
                                          BYTE **pString){
    LogDebug("get capital R0");
    return TSS_SUCCESS;
}

TSS_RESULT obj_daaissuerkey_get_daa_handle(TSS_HDAA_ISSUER_KEY key,
                                           TPM_HANDLE *pInt){
    LogDebug("get daa handle");
    return TSS_SUCCESS;
}



TSS_RESULT
obj_daaissuerkey_get_attribs(TSS_HDAA hDaa, UINT32 numberIssuerAttributes, UINT32 numberPlatformAttributes )
{
struct tsp_object *obj;

if ((obj = obj_list_get_obj(&daaissuerkey_list, hDaa)) == NULL)
return TSPERR(TSS_E_INVALID_HANDLE);
// TODO return attributes from issuer key? fixit
    printf("issuer key get attributes");
//*tspContext = obj->tspContext;

//obj_list_put(&daaissuerkey_list);

return TSS_SUCCESS;
}

static TSS_RESULT
obj_daaissuerkey_get_and_lock_data(TSS_HDAA hDaa, struct tr_daa_obj **daa)
{
    struct tsp_object *obj;

    if ((obj = obj_list_get_obj(&daaissuerkey_list, hDaa)) == NULL)
        return TSPERR(TSS_E_INVALID_HANDLE);
    *daa = obj->data;
    return TSS_SUCCESS;
}

TSS_RESULT
obj_daaissuerkey_get_handle_tpm(TSS_HDAA hDAA, TPM_HANDLE *hTPM) {
    struct tr_daa_obj *daa_struct;
    TSS_RESULT result;

    if( (result = obj_daaissuerkey_get_and_lock_data( hDAA, &daa_struct)) != TSS_SUCCESS) return result;
    *hTPM = daa_struct->tpm_handle;
    obj_list_put(&daaissuerkey_list);
    return TSS_SUCCESS;
}

TSS_RESULT
obj_daaissuerkey_set_handle_tpm(TSS_HDAA hDAA, TPM_HANDLE hTPM) {
    struct tr_daa_obj *daa_struct;
    TSS_RESULT result;

    if( (result = obj_daaissuerkey_get_and_lock_data( hDAA, &daa_struct)) != TSS_SUCCESS) return result;
    daa_struct->tpm_handle = hTPM;
    obj_list_put(&daaissuerkey_list);
    return TSS_SUCCESS;
}

TSS_RESULT
obj_daaissuerkey_get_session_handle(TSS_HDAA hDAA, UINT32 *session_handle) {
    struct tr_daa_obj *daa_struct;
    TSS_RESULT result;

    if( (result = obj_daaissuerkey_get_and_lock_data( hDAA, &daa_struct)) != TSS_SUCCESS) return result;
    *session_handle = daa_struct->session_handle;

    obj_list_put(&daaissuerkey_list);
    return TSS_SUCCESS;
}

TSS_RESULT
obj_daaissuerkey_set_session_handle(TSS_HDAA hDAA, UINT32 session_handle) {
    struct tr_daa_obj *daa_struct;
    TSS_RESULT result;

    if( (result = obj_daaissuerkey_get_and_lock_data( hDAA, &daa_struct)) != TSS_SUCCESS) return result;
    daa_struct->session_handle = session_handle;
    obj_list_put(&daaissuerkey_list);
    return TSS_SUCCESS;
}
