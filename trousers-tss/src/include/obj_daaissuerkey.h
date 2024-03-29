
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2007
 *
 */

#ifndef _OBJ_DAAISSUERKEY_H_
#define _OBJ_DAAISSUERKEY_H_

//#ifdef TSS_BUILD_DAA

/* structures */
struct tr_daaissuerkey_obj {
	UINT32 session_handle;
	TPM_HANDLE tpm_handle;
};

/* prototypes */
void       daaissuerkey_free(void *data);
TSS_RESULT obj_daaissuerkey_add(TSS_HCONTEXT tspContext, TSS_HOBJECT *phObject);
TSS_RESULT obj_daaissuerkey_remove(TSS_HDAA_ISSUER_KEY, TSS_HCONTEXT);
TSS_BOOL   obj_is_daaissuerkey(TSS_HDAA_ISSUER_KEY);
TSS_RESULT obj_daaissuerkey_get_tsp_context(TSS_HDAA_ISSUER_KEY, TSS_HCONTEXT *);
TSS_RESULT obj_daaissuerkey_set_daa_handle(TSS_HDAA_ISSUER_KEY, TPM_HANDLE);
TSS_RESULT obj_daaissuerkey_get_capitalSprime(TSS_HDAA_ISSUER_KEY, UINT32 * , BYTE **);
TSS_RESULT obj_daaissuerkey_get_daa_issuer(TSS_HDAA_ISSUER_KEY, const int *, BYTE **);
TSS_RESULT obj_daaissuerkey_get_modulus(TSS_HDAA_ISSUER_KEY, UINT32 *, BYTE **);
TSS_RESULT obj_daaissuerkey_get_capitalR1(TSS_HDAA_ISSUER_KEY, UINT32 *, BYTE **);
TSS_RESULT obj_daaissuerkey_get_capitalS(TSS_HDAA_ISSUER_KEY, UINT32 *, BYTE **);
TSS_RESULT obj_daaissuerkey_get_capitalR0(TSS_HDAA_ISSUER_KEY, UINT32 *, BYTE **);
TSS_RESULT obj_daaissuerkey_get_daa_handle(TSS_HDAA_ISSUER_KEY, TPM_HANDLE *);
TSS_RESULT obj_tpm_is_connected(TSS_HTPM, TSS_HCONTEXT *);
TSS_RESULT obj_daaissuerkey_get_handle_tpm(TSS_HDAA_ISSUER_KEY, TPM_HANDLE *);
TSS_RESULT obj_daaissuerkey_set_handle_tpm(TSS_HDAA_ISSUER_KEY, TPM_HANDLE);
TSS_RESULT obj_daaissuerkey_get_session_handle(TSS_HDAA_ISSUER_KEY, UINT32 *);
TSS_RESULT obj_daaissuerkey_set_session_handle(TSS_HDAA_ISSUER_KEY, UINT32);
TSS_RESULT obj_daaissuerkey_get_attribs(TSS_HDAA_ISSUER_KEY, UINT32, UINT32);

#define DAAISSUERKEY_LIST_DECLARE		struct obj_list daaissuerkey_list
#define DAAISSUERKEY_LIST_DECLARE_EXTERN	extern struct obj_list daaissuerkey_list
#define DAAISSUERKEY_LIST_INIT()		tspi_list_init(&daaissuerkey_list)
#define DAAISSUERKEY_LIST_CONNECT(a,b)		obj_connectContext_list(&daaissuerkey_list, a, b)
#define DAAISSUERKEY_LIST_CLOSE(a)		obj_list_close(&daaissuerkey_list, \
							       &daaissuerkey_free, a)

//#else
//
//#define obj_is_daaissuerkey(a)	FALSE
//
//#define DAAISSUERKEY_LIST_DECLARE
//#define DAAISSUERKEY_LIST_DECLARE_EXTERN
//#define DAAISSUERKEY_LIST_INIT()
//#define DAAISSUERKEY_LIST_CONNECT(a,b)
//#define DAAISSUERKEY_LIST_CLOSE(a)
//
//#endif

#endif
