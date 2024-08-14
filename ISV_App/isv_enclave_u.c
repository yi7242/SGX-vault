#include "isv_enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_ra_init_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t* ms_ra_ctx;
} ms_ecall_ra_init_t;

typedef struct ms_ecall_ra_close_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_ra_ctx;
} ms_ecall_ra_close_t;

typedef struct ms_ecall_sample_addition_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_ra_ctx;
	uint8_t* ms_cipher1;
	size_t ms_cipher1_len;
	uint8_t* ms_cipher2;
	size_t ms_cipher2_len;
	uint8_t* ms_iv;
	uint8_t* ms_tag1;
	uint8_t* ms_tag2;
	uint8_t* ms_result;
	size_t* ms_result_len;
	uint8_t* ms_iv_result;
	uint8_t* ms_tag_result;
} ms_ecall_sample_addition_t;

typedef struct ms_ecall_master_sealing_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_ra_ctx;
	uint8_t* ms_master;
	size_t ms_master_len;
	uint8_t* ms_iv;
	uint8_t* ms_master_tag;
	int ms_policy;
} ms_ecall_master_sealing_t;

typedef struct ms_calc_sealed_len_t {
	int ms_retval;
	int ms_message_len;
} ms_calc_sealed_len_t;

typedef struct ms_do_sealing_t {
	uint8_t* ms_message;
	int ms_message_len;
	uint8_t* ms_sealed;
	int ms_sealed_len;
	int ms_policy;
} ms_do_sealing_t;

typedef struct ms_calc_unsealed_len_t {
	int ms_retval;
	uint8_t* ms_sealed;
	int ms_sealed_len;
} ms_calc_unsealed_len_t;

typedef struct ms_do_unsealing_t {
	uint8_t* ms_sealed;
	int ms_sealed_len;
	uint8_t* ms_unsealed;
	int ms_unsealed_len;
	int* ms_error_flag;
} ms_do_unsealing_t;

typedef struct ms_sl_init_switchless_t {
	sgx_status_t ms_retval;
	void* ms_sl_data;
} ms_sl_init_switchless_t;

typedef struct ms_sl_run_switchless_tworker_t {
	sgx_status_t ms_retval;
} ms_sl_run_switchless_tworker_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const sgx_ra_msg2_t* ms_p_msg2;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
	int ms_log_type;
} ms_ocall_print_t;

typedef struct ms_ocall_print_status_t {
	sgx_status_t ms_st;
} ms_ocall_print_status_t;

typedef struct ms_ocall_print_binary_t {
	uint8_t* ms_bin;
	int ms_bin_size;
	int ms_log_type;
} ms_ocall_print_binary_t;

typedef struct ms_ocall_store_sealed_master_t {
	int ms_retval;
	const char* ms_sealed;
	int ms_sealed_len;
} ms_ocall_store_sealed_master_t;

typedef struct ms_ocall_get_sealed_master_t {
	int ms_retval;
	uint8_t* ms_sealed;
	int* ms_sealed_len;
} ms_ocall_get_sealed_master_t;

static sgx_status_t SGX_CDECL isv_enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str, ms->ms_log_type);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_ocall_print_status(void* pms)
{
	ms_ocall_print_status_t* ms = SGX_CAST(ms_ocall_print_status_t*, pms);
	ocall_print_status(ms->ms_st);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_ocall_print_binary(void* pms)
{
	ms_ocall_print_binary_t* ms = SGX_CAST(ms_ocall_print_binary_t*, pms);
	ocall_print_binary(ms->ms_bin, ms->ms_bin_size, ms->ms_log_type);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_ocall_store_sealed_master(void* pms)
{
	ms_ocall_store_sealed_master_t* ms = SGX_CAST(ms_ocall_store_sealed_master_t*, pms);
	ms->ms_retval = ocall_store_sealed_master(ms->ms_sealed, ms->ms_sealed_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL isv_enclave_ocall_get_sealed_master(void* pms)
{
	ms_ocall_get_sealed_master_t* ms = SGX_CAST(ms_ocall_get_sealed_master_t*, pms);
	ms->ms_retval = ocall_get_sealed_master(ms->ms_sealed, ms->ms_sealed_len);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_isv_enclave = {
	5,
	{
		(void*)isv_enclave_ocall_print,
		(void*)isv_enclave_ocall_print_status,
		(void*)isv_enclave_ocall_print_binary,
		(void*)isv_enclave_ocall_store_sealed_master,
		(void*)isv_enclave_ocall_get_sealed_master,
	}
};
sgx_status_t ecall_ra_init(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t* ra_ctx)
{
	sgx_status_t status;
	ms_ecall_ra_init_t ms;
	ms.ms_ra_ctx = ra_ctx;
	status = sgx_ecall(eid, 0, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t ra_ctx)
{
	sgx_status_t status;
	ms_ecall_ra_close_t ms;
	ms.ms_ra_ctx = ra_ctx;
	status = sgx_ecall(eid, 1, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sample_addition(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t ra_ctx, uint8_t* cipher1, size_t cipher1_len, uint8_t* cipher2, size_t cipher2_len, uint8_t* iv, uint8_t* tag1, uint8_t* tag2, uint8_t* result, size_t* result_len, uint8_t* iv_result, uint8_t* tag_result)
{
	sgx_status_t status;
	ms_ecall_sample_addition_t ms;
	ms.ms_ra_ctx = ra_ctx;
	ms.ms_cipher1 = cipher1;
	ms.ms_cipher1_len = cipher1_len;
	ms.ms_cipher2 = cipher2;
	ms.ms_cipher2_len = cipher2_len;
	ms.ms_iv = iv;
	ms.ms_tag1 = tag1;
	ms.ms_tag2 = tag2;
	ms.ms_result = result;
	ms.ms_result_len = result_len;
	ms.ms_iv_result = iv_result;
	ms.ms_tag_result = tag_result;
	status = sgx_ecall(eid, 2, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_master_sealing(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t ra_ctx, uint8_t* master, size_t master_len, uint8_t* iv, uint8_t* master_tag, int policy)
{
	sgx_status_t status;
	ms_ecall_master_sealing_t ms;
	ms.ms_ra_ctx = ra_ctx;
	ms.ms_master = master;
	ms.ms_master_len = master_len;
	ms.ms_iv = iv;
	ms.ms_master_tag = master_tag;
	ms.ms_policy = policy;
	status = sgx_ecall(eid, 3, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t calc_sealed_len(sgx_enclave_id_t eid, int* retval, int message_len)
{
	sgx_status_t status;
	ms_calc_sealed_len_t ms;
	ms.ms_message_len = message_len;
	status = sgx_ecall(eid, 4, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t do_sealing(sgx_enclave_id_t eid, uint8_t* message, int message_len, uint8_t* sealed, int sealed_len, int policy)
{
	sgx_status_t status;
	ms_do_sealing_t ms;
	ms.ms_message = message;
	ms.ms_message_len = message_len;
	ms.ms_sealed = sealed;
	ms.ms_sealed_len = sealed_len;
	ms.ms_policy = policy;
	status = sgx_ecall(eid, 5, &ocall_table_isv_enclave, &ms);
	return status;
}

sgx_status_t calc_unsealed_len(sgx_enclave_id_t eid, int* retval, uint8_t* sealed, int sealed_len)
{
	sgx_status_t status;
	ms_calc_unsealed_len_t ms;
	ms.ms_sealed = sealed;
	ms.ms_sealed_len = sealed_len;
	status = sgx_ecall(eid, 6, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t do_unsealing(sgx_enclave_id_t eid, uint8_t* sealed, int sealed_len, uint8_t* unsealed, int unsealed_len, int* error_flag)
{
	sgx_status_t status;
	ms_do_unsealing_t ms;
	ms.ms_sealed = sealed;
	ms.ms_sealed_len = sealed_len;
	ms.ms_unsealed = unsealed;
	ms.ms_unsealed_len = unsealed_len;
	ms.ms_error_flag = error_flag;
	status = sgx_ecall(eid, 7, &ocall_table_isv_enclave, &ms);
	return status;
}

sgx_status_t sl_init_switchless(sgx_enclave_id_t eid, sgx_status_t* retval, void* sl_data)
{
	sgx_status_t status;
	ms_sl_init_switchless_t ms;
	ms.ms_sl_data = sl_data;
	status = sgx_ecall(eid, 8, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sl_run_switchless_tworker(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_sl_run_switchless_tworker_t ms;
	status = sgx_ecall(eid, 9, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 10, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = p_msg2;
	ms.ms_p_qe_target = p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 11, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 12, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

