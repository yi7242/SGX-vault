#ifndef ISV_ENCLAVE_T_H__
#define ISV_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_tkey_exchange.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ecall_ra_init(sgx_ra_context_t* ra_ctx);
sgx_status_t ecall_ra_close(sgx_ra_context_t ra_ctx);
sgx_status_t ecall_sample_addition(sgx_ra_context_t ra_ctx, uint8_t* cipher1, size_t cipher1_len, uint8_t* cipher2, size_t cipher2_len, uint8_t* iv, uint8_t* tag1, uint8_t* tag2, uint8_t* result, size_t* result_len, uint8_t* iv_result, uint8_t* tag_result);
sgx_status_t ecall_master_sealing(sgx_ra_context_t ra_ctx, uint8_t* master, size_t master_len, uint8_t* iv, uint8_t* master_tag, int policy);
int calc_sealed_len(int message_len);
void do_sealing(uint8_t* message, int message_len, uint8_t* sealed, int sealed_len, int policy);
int calc_unsealed_len(uint8_t* sealed, int sealed_len);
void do_unsealing(uint8_t* sealed, int sealed_len, uint8_t* unsealed, int unsealed_len, int* error_flag);
sgx_status_t sl_init_switchless(void* sl_data);
sgx_status_t sl_run_switchless_tworker(void);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

sgx_status_t SGX_CDECL ocall_print(const char* str, int log_type);
sgx_status_t SGX_CDECL ocall_print_status(sgx_status_t st);
sgx_status_t SGX_CDECL ocall_print_binary(uint8_t* bin, int bin_size, int log_type);
sgx_status_t SGX_CDECL ocall_store_sealed_master(int* retval, const char* sealed, int sealed_len);
sgx_status_t SGX_CDECL ocall_get_sealed_len(int* retval, const char* file_name);
sgx_status_t SGX_CDECL ocall_get_sealed_master(int* retval, uint8_t* sealed, int* sealed_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
