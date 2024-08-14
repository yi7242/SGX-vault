#include "isv_enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

typedef struct ms_ocall_get_sealed_len_t {
	int ms_retval;
	const char* ms_file_name;
} ms_ocall_get_sealed_len_t;

typedef struct ms_ocall_get_sealed_master_t {
	int ms_retval;
	uint8_t* ms_sealed;
	int* ms_sealed_len;
} ms_ocall_get_sealed_master_t;

static sgx_status_t SGX_CDECL sgx_ecall_ra_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ra_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_ra_init_t* ms = SGX_CAST(ms_ecall_ra_init_t*, pms);
	ms_ecall_ra_init_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_ra_init_t), ms, sizeof(ms_ecall_ra_init_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_ra_ctx = __in_ms.ms_ra_ctx;
	size_t _len_ra_ctx = sizeof(sgx_ra_context_t);
	sgx_ra_context_t* _in_ra_ctx = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_ra_ctx, _len_ra_ctx);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ra_ctx != NULL && _len_ra_ctx != 0) {
		if ((_in_ra_ctx = (sgx_ra_context_t*)malloc(_len_ra_ctx)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ra_ctx, 0, _len_ra_ctx);
	}
	_in_retval = ecall_ra_init(_in_ra_ctx);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_ra_ctx) {
		if (memcpy_verw_s(_tmp_ra_ctx, _len_ra_ctx, _in_ra_ctx, _len_ra_ctx)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ra_ctx) free(_in_ra_ctx);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_ra_close(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ra_close_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_ra_close_t* ms = SGX_CAST(ms_ecall_ra_close_t*, pms);
	ms_ecall_ra_close_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_ra_close_t), ms, sizeof(ms_ecall_ra_close_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = ecall_ra_close(__in_ms.ms_ra_ctx);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sample_addition(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sample_addition_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sample_addition_t* ms = SGX_CAST(ms_ecall_sample_addition_t*, pms);
	ms_ecall_sample_addition_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_sample_addition_t), ms, sizeof(ms_ecall_sample_addition_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_cipher1 = __in_ms.ms_cipher1;
	size_t _tmp_cipher1_len = __in_ms.ms_cipher1_len;
	size_t _len_cipher1 = _tmp_cipher1_len;
	uint8_t* _in_cipher1 = NULL;
	uint8_t* _tmp_cipher2 = __in_ms.ms_cipher2;
	size_t _tmp_cipher2_len = __in_ms.ms_cipher2_len;
	size_t _len_cipher2 = _tmp_cipher2_len;
	uint8_t* _in_cipher2 = NULL;
	uint8_t* _tmp_iv = __in_ms.ms_iv;
	size_t _len_iv = 12;
	uint8_t* _in_iv = NULL;
	uint8_t* _tmp_tag1 = __in_ms.ms_tag1;
	size_t _len_tag1 = 16;
	uint8_t* _in_tag1 = NULL;
	uint8_t* _tmp_tag2 = __in_ms.ms_tag2;
	size_t _len_tag2 = 16;
	uint8_t* _in_tag2 = NULL;
	uint8_t* _tmp_result = __in_ms.ms_result;
	size_t _len_result = 32;
	uint8_t* _in_result = NULL;
	size_t* _tmp_result_len = __in_ms.ms_result_len;
	size_t _len_result_len = sizeof(size_t);
	size_t* _in_result_len = NULL;
	uint8_t* _tmp_iv_result = __in_ms.ms_iv_result;
	size_t _len_iv_result = 12;
	uint8_t* _in_iv_result = NULL;
	uint8_t* _tmp_tag_result = __in_ms.ms_tag_result;
	size_t _len_tag_result = 16;
	uint8_t* _in_tag_result = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_cipher1, _len_cipher1);
	CHECK_UNIQUE_POINTER(_tmp_cipher2, _len_cipher2);
	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);
	CHECK_UNIQUE_POINTER(_tmp_tag1, _len_tag1);
	CHECK_UNIQUE_POINTER(_tmp_tag2, _len_tag2);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);
	CHECK_UNIQUE_POINTER(_tmp_result_len, _len_result_len);
	CHECK_UNIQUE_POINTER(_tmp_iv_result, _len_iv_result);
	CHECK_UNIQUE_POINTER(_tmp_tag_result, _len_tag_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_cipher1 != NULL && _len_cipher1 != 0) {
		if ( _len_cipher1 % sizeof(*_tmp_cipher1) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_cipher1 = (uint8_t*)malloc(_len_cipher1);
		if (_in_cipher1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cipher1, _len_cipher1, _tmp_cipher1, _len_cipher1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cipher2 != NULL && _len_cipher2 != 0) {
		if ( _len_cipher2 % sizeof(*_tmp_cipher2) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_cipher2 = (uint8_t*)malloc(_len_cipher2);
		if (_in_cipher2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cipher2, _len_cipher2, _tmp_cipher2, _len_cipher2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_iv != NULL && _len_iv != 0) {
		if ( _len_iv % sizeof(*_tmp_iv) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_iv = (uint8_t*)malloc(_len_iv);
		if (_in_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_iv, _len_iv, _tmp_iv, _len_iv)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_tag1 != NULL && _len_tag1 != 0) {
		if ( _len_tag1 % sizeof(*_tmp_tag1) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tag1 = (uint8_t*)malloc(_len_tag1);
		if (_in_tag1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tag1, _len_tag1, _tmp_tag1, _len_tag1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_tag2 != NULL && _len_tag2 != 0) {
		if ( _len_tag2 % sizeof(*_tmp_tag2) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tag2 = (uint8_t*)malloc(_len_tag2);
		if (_in_tag2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tag2, _len_tag2, _tmp_tag2, _len_tag2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	if (_tmp_result_len != NULL && _len_result_len != 0) {
		if ( _len_result_len % sizeof(*_tmp_result_len) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result_len = (size_t*)malloc(_len_result_len)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result_len, 0, _len_result_len);
	}
	if (_tmp_iv_result != NULL && _len_iv_result != 0) {
		if ( _len_iv_result % sizeof(*_tmp_iv_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_iv_result = (uint8_t*)malloc(_len_iv_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_iv_result, 0, _len_iv_result);
	}
	if (_tmp_tag_result != NULL && _len_tag_result != 0) {
		if ( _len_tag_result % sizeof(*_tmp_tag_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_tag_result = (uint8_t*)malloc(_len_tag_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_tag_result, 0, _len_tag_result);
	}
	_in_retval = ecall_sample_addition(__in_ms.ms_ra_ctx, _in_cipher1, _tmp_cipher1_len, _in_cipher2, _tmp_cipher2_len, _in_iv, _in_tag1, _in_tag2, _in_result, _in_result_len, _in_iv_result, _in_tag_result);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_result_len) {
		if (memcpy_verw_s(_tmp_result_len, _len_result_len, _in_result_len, _len_result_len)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_iv_result) {
		if (memcpy_verw_s(_tmp_iv_result, _len_iv_result, _in_iv_result, _len_iv_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_tag_result) {
		if (memcpy_verw_s(_tmp_tag_result, _len_tag_result, _in_tag_result, _len_tag_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_cipher1) free(_in_cipher1);
	if (_in_cipher2) free(_in_cipher2);
	if (_in_iv) free(_in_iv);
	if (_in_tag1) free(_in_tag1);
	if (_in_tag2) free(_in_tag2);
	if (_in_result) free(_in_result);
	if (_in_result_len) free(_in_result_len);
	if (_in_iv_result) free(_in_iv_result);
	if (_in_tag_result) free(_in_tag_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_master_sealing(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_master_sealing_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_master_sealing_t* ms = SGX_CAST(ms_ecall_master_sealing_t*, pms);
	ms_ecall_master_sealing_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_master_sealing_t), ms, sizeof(ms_ecall_master_sealing_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_master = __in_ms.ms_master;
	size_t _tmp_master_len = __in_ms.ms_master_len;
	size_t _len_master = _tmp_master_len;
	uint8_t* _in_master = NULL;
	uint8_t* _tmp_iv = __in_ms.ms_iv;
	size_t _len_iv = 12;
	uint8_t* _in_iv = NULL;
	uint8_t* _tmp_master_tag = __in_ms.ms_master_tag;
	size_t _len_master_tag = 16;
	uint8_t* _in_master_tag = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_master, _len_master);
	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);
	CHECK_UNIQUE_POINTER(_tmp_master_tag, _len_master_tag);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master != NULL && _len_master != 0) {
		if ( _len_master % sizeof(*_tmp_master) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_master = (uint8_t*)malloc(_len_master);
		if (_in_master == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master, _len_master, _tmp_master, _len_master)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_iv != NULL && _len_iv != 0) {
		if ( _len_iv % sizeof(*_tmp_iv) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_iv = (uint8_t*)malloc(_len_iv);
		if (_in_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_iv, _len_iv, _tmp_iv, _len_iv)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_master_tag != NULL && _len_master_tag != 0) {
		if ( _len_master_tag % sizeof(*_tmp_master_tag) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_master_tag = (uint8_t*)malloc(_len_master_tag);
		if (_in_master_tag == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_tag, _len_master_tag, _tmp_master_tag, _len_master_tag)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_master_sealing(__in_ms.ms_ra_ctx, _in_master, _tmp_master_len, _in_iv, _in_master_tag, __in_ms.ms_policy);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_master) free(_in_master);
	if (_in_iv) free(_in_iv);
	if (_in_master_tag) free(_in_master_tag);
	return status;
}

static sgx_status_t SGX_CDECL sgx_calc_sealed_len(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_calc_sealed_len_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_calc_sealed_len_t* ms = SGX_CAST(ms_calc_sealed_len_t*, pms);
	ms_calc_sealed_len_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_calc_sealed_len_t), ms, sizeof(ms_calc_sealed_len_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = calc_sealed_len(__in_ms.ms_message_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_do_sealing(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_do_sealing_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_do_sealing_t* ms = SGX_CAST(ms_do_sealing_t*, pms);
	ms_do_sealing_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_do_sealing_t), ms, sizeof(ms_do_sealing_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_message = __in_ms.ms_message;
	int _tmp_message_len = __in_ms.ms_message_len;
	size_t _len_message = _tmp_message_len;
	uint8_t* _in_message = NULL;
	uint8_t* _tmp_sealed = __in_ms.ms_sealed;
	int _tmp_sealed_len = __in_ms.ms_sealed_len;
	size_t _len_sealed = _tmp_sealed_len;
	uint8_t* _in_sealed = NULL;

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);
	CHECK_UNIQUE_POINTER(_tmp_sealed, _len_sealed);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_message != NULL && _len_message != 0) {
		if ( _len_message % sizeof(*_tmp_message) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_message = (uint8_t*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_message, _len_message, _tmp_message, _len_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed != NULL && _len_sealed != 0) {
		if ( _len_sealed % sizeof(*_tmp_sealed) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed = (uint8_t*)malloc(_len_sealed);
		if (_in_sealed == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed, _len_sealed, _tmp_sealed, _len_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	do_sealing(_in_message, _tmp_message_len, _in_sealed, _tmp_sealed_len, __in_ms.ms_policy);
	if (_in_sealed) {
		if (memcpy_verw_s(_tmp_sealed, _len_sealed, _in_sealed, _len_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_message) free(_in_message);
	if (_in_sealed) free(_in_sealed);
	return status;
}

static sgx_status_t SGX_CDECL sgx_calc_unsealed_len(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_calc_unsealed_len_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_calc_unsealed_len_t* ms = SGX_CAST(ms_calc_unsealed_len_t*, pms);
	ms_calc_unsealed_len_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_calc_unsealed_len_t), ms, sizeof(ms_calc_unsealed_len_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed = __in_ms.ms_sealed;
	int _tmp_sealed_len = __in_ms.ms_sealed_len;
	size_t _len_sealed = _tmp_sealed_len;
	uint8_t* _in_sealed = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sealed, _len_sealed);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed != NULL && _len_sealed != 0) {
		if ( _len_sealed % sizeof(*_tmp_sealed) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed = (uint8_t*)malloc(_len_sealed);
		if (_in_sealed == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed, _len_sealed, _tmp_sealed, _len_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = calc_unsealed_len(_in_sealed, _tmp_sealed_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_sealed) free(_in_sealed);
	return status;
}

static sgx_status_t SGX_CDECL sgx_do_unsealing(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_do_unsealing_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_do_unsealing_t* ms = SGX_CAST(ms_do_unsealing_t*, pms);
	ms_do_unsealing_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_do_unsealing_t), ms, sizeof(ms_do_unsealing_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed = __in_ms.ms_sealed;
	int _tmp_sealed_len = __in_ms.ms_sealed_len;
	size_t _len_sealed = _tmp_sealed_len;
	uint8_t* _in_sealed = NULL;
	uint8_t* _tmp_unsealed = __in_ms.ms_unsealed;
	int _tmp_unsealed_len = __in_ms.ms_unsealed_len;
	size_t _len_unsealed = _tmp_unsealed_len;
	uint8_t* _in_unsealed = NULL;
	int* _tmp_error_flag = __in_ms.ms_error_flag;
	size_t _len_error_flag = sizeof(int);
	int* _in_error_flag = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed, _len_sealed);
	CHECK_UNIQUE_POINTER(_tmp_unsealed, _len_unsealed);
	CHECK_UNIQUE_POINTER(_tmp_error_flag, _len_error_flag);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed != NULL && _len_sealed != 0) {
		if ( _len_sealed % sizeof(*_tmp_sealed) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed = (uint8_t*)malloc(_len_sealed);
		if (_in_sealed == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed, _len_sealed, _tmp_sealed, _len_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_unsealed != NULL && _len_unsealed != 0) {
		if ( _len_unsealed % sizeof(*_tmp_unsealed) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_unsealed = (uint8_t*)malloc(_len_unsealed);
		if (_in_unsealed == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_unsealed, _len_unsealed, _tmp_unsealed, _len_unsealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_error_flag != NULL && _len_error_flag != 0) {
		if ( _len_error_flag % sizeof(*_tmp_error_flag) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_error_flag = (int*)malloc(_len_error_flag)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_error_flag, 0, _len_error_flag);
	}
	do_unsealing(_in_sealed, _tmp_sealed_len, _in_unsealed, _tmp_unsealed_len, _in_error_flag);
	if (_in_unsealed) {
		if (memcpy_verw_s(_tmp_unsealed, _len_unsealed, _in_unsealed, _len_unsealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_error_flag) {
		if (memcpy_verw_s(_tmp_error_flag, _len_error_flag, _in_error_flag, _len_error_flag)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed) free(_in_sealed);
	if (_in_unsealed) free(_in_unsealed);
	if (_in_error_flag) free(_in_error_flag);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sl_init_switchless(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sl_init_switchless_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sl_init_switchless_t* ms = SGX_CAST(ms_sl_init_switchless_t*, pms);
	ms_sl_init_switchless_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_sl_init_switchless_t), ms, sizeof(ms_sl_init_switchless_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_sl_data = __in_ms.ms_sl_data;
	sgx_status_t _in_retval;


	_in_retval = sl_init_switchless(_tmp_sl_data);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_sl_run_switchless_tworker(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sl_run_switchless_tworker_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sl_run_switchless_tworker_t* ms = SGX_CAST(ms_sl_run_switchless_tworker_t*, pms);
	ms_sl_run_switchless_tworker_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_sl_run_switchless_tworker_t), ms, sizeof(ms_sl_run_switchless_tworker_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = sl_run_switchless_tworker();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	ms_sgx_ra_get_ga_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_sgx_ra_get_ga_t), ms, sizeof(ms_sgx_ra_get_ga_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = __in_ms.ms_g_a;
	size_t _len_g_a = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_g_a = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_a != NULL && _len_g_a != 0) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}
	_in_retval = sgx_ra_get_ga(__in_ms.ms_context, _in_g_a);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_g_a) {
		if (memcpy_verw_s(_tmp_g_a, _len_g_a, _in_g_a, _len_g_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_g_a) free(_in_g_a);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	ms_sgx_ra_proc_msg2_trusted_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_sgx_ra_proc_msg2_trusted_t), ms, sizeof(ms_sgx_ra_proc_msg2_trusted_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const sgx_ra_msg2_t* _tmp_p_msg2 = __in_ms.ms_p_msg2;
	size_t _len_p_msg2 = sizeof(sgx_ra_msg2_t);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	const sgx_target_info_t* _tmp_p_qe_target = __in_ms.ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = __in_ms.ms_p_report;
	size_t _len_p_report = sizeof(sgx_report_t);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = __in_ms.ms_p_nonce;
	size_t _len_p_nonce = sizeof(sgx_quote_nonce_t);
	sgx_quote_nonce_t* _in_p_nonce = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_msg2 != NULL && _len_p_msg2 != 0) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_msg2, _len_p_msg2, _tmp_p_msg2, _len_p_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_qe_target != NULL && _len_p_qe_target != 0) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_qe_target, _len_p_qe_target, _tmp_p_qe_target, _len_p_qe_target)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_report != NULL && _len_p_report != 0) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL && _len_p_nonce != 0) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}
	_in_retval = sgx_ra_proc_msg2_trusted(__in_ms.ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_p_report) {
		if (memcpy_verw_s(_tmp_p_report, _len_p_report, _in_p_report, _len_p_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_nonce) {
		if (memcpy_verw_s(_tmp_p_nonce, _len_p_nonce, _in_p_nonce, _len_p_nonce)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_msg2) free(_in_p_msg2);
	if (_in_p_qe_target) free(_in_p_qe_target);
	if (_in_p_report) free(_in_p_report);
	if (_in_p_nonce) free(_in_p_nonce);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	ms_sgx_ra_get_msg3_trusted_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_sgx_ra_get_msg3_trusted_t), ms, sizeof(ms_sgx_ra_get_msg3_trusted_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = __in_ms.ms_qe_report;
	size_t _len_qe_report = sizeof(sgx_report_t);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = __in_ms.ms_p_msg3;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_qe_report != NULL && _len_qe_report != 0) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_qe_report, _len_qe_report, _tmp_qe_report, _len_qe_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = sgx_ra_get_msg3_trusted(__in_ms.ms_context, __in_ms.ms_quote_size, _in_qe_report, _tmp_p_msg3, __in_ms.ms_msg3_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_qe_report) free(_in_qe_report);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[13];
} g_ecall_table = {
	13,
	{
		{(void*)(uintptr_t)sgx_ecall_ra_init, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_ra_close, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sample_addition, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_master_sealing, 0, 0},
		{(void*)(uintptr_t)sgx_calc_sealed_len, 0, 0},
		{(void*)(uintptr_t)sgx_do_sealing, 0, 0},
		{(void*)(uintptr_t)sgx_calc_unsealed_len, 0, 0},
		{(void*)(uintptr_t)sgx_do_unsealing, 0, 0},
		{(void*)(uintptr_t)sgx_sl_init_switchless, 0, 0},
		{(void*)(uintptr_t)sgx_sl_run_switchless_tworker, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[6][13];
} g_dyn_entry_table = {
	6,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str, int log_type)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	if (memcpy_verw_s(&ms->ms_log_type, sizeof(ms->ms_log_type), &log_type, sizeof(log_type))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_status(sgx_status_t st)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_print_status_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_status_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_status_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_status_t));
	ocalloc_size -= sizeof(ms_ocall_print_status_t);

	if (memcpy_verw_s(&ms->ms_st, sizeof(ms->ms_st), &st, sizeof(st))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_binary(uint8_t* bin, int bin_size, int log_type)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_bin = bin_size;

	ms_ocall_print_binary_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_binary_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(bin, _len_bin);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (bin != NULL) ? _len_bin : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_binary_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_binary_t));
	ocalloc_size -= sizeof(ms_ocall_print_binary_t);

	if (bin != NULL) {
		if (memcpy_verw_s(&ms->ms_bin, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_bin % sizeof(*bin) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, bin, _len_bin)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_bin);
		ocalloc_size -= _len_bin;
	} else {
		ms->ms_bin = NULL;
	}

	if (memcpy_verw_s(&ms->ms_bin_size, sizeof(ms->ms_bin_size), &bin_size, sizeof(bin_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_log_type, sizeof(ms->ms_log_type), &log_type, sizeof(log_type))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_store_sealed_master(int* retval, const char* sealed, int sealed_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealed = sealed_len;

	ms_ocall_store_sealed_master_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_store_sealed_master_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(sealed, _len_sealed);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed != NULL) ? _len_sealed : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_store_sealed_master_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_store_sealed_master_t));
	ocalloc_size -= sizeof(ms_ocall_store_sealed_master_t);

	if (sealed != NULL) {
		if (memcpy_verw_s(&ms->ms_sealed, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_sealed % sizeof(*sealed) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, sealed, _len_sealed)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealed);
		ocalloc_size -= _len_sealed;
	} else {
		ms->ms_sealed = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sealed_len, sizeof(ms->ms_sealed_len), &sealed_len, sizeof(sealed_len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_sealed_len(int* retval, const char* file_name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file_name = file_name ? strlen(file_name) + 1 : 0;

	ms_ocall_get_sealed_len_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_sealed_len_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(file_name, _len_file_name);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (file_name != NULL) ? _len_file_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_sealed_len_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_sealed_len_t));
	ocalloc_size -= sizeof(ms_ocall_get_sealed_len_t);

	if (file_name != NULL) {
		if (memcpy_verw_s(&ms->ms_file_name, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_file_name % sizeof(*file_name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, file_name, _len_file_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_file_name);
		ocalloc_size -= _len_file_name;
	} else {
		ms->ms_file_name = NULL;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_sealed_master(int* retval, uint8_t* sealed, int* sealed_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealed = 1000;
	size_t _len_sealed_len = sizeof(int);

	ms_ocall_get_sealed_master_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_sealed_master_t);
	void *__tmp = NULL;

	void *__tmp_sealed = NULL;
	void *__tmp_sealed_len = NULL;

	CHECK_ENCLAVE_POINTER(sealed, _len_sealed);
	CHECK_ENCLAVE_POINTER(sealed_len, _len_sealed_len);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed != NULL) ? _len_sealed : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed_len != NULL) ? _len_sealed_len : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_sealed_master_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_sealed_master_t));
	ocalloc_size -= sizeof(ms_ocall_get_sealed_master_t);

	if (sealed != NULL) {
		if (memcpy_verw_s(&ms->ms_sealed, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_sealed = __tmp;
		if (_len_sealed % sizeof(*sealed) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_sealed, 0, _len_sealed);
		__tmp = (void *)((size_t)__tmp + _len_sealed);
		ocalloc_size -= _len_sealed;
	} else {
		ms->ms_sealed = NULL;
	}

	if (sealed_len != NULL) {
		if (memcpy_verw_s(&ms->ms_sealed_len, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_sealed_len = __tmp;
		if (_len_sealed_len % sizeof(*sealed_len) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_sealed_len, 0, _len_sealed_len);
		__tmp = (void *)((size_t)__tmp + _len_sealed_len);
		ocalloc_size -= _len_sealed_len;
	} else {
		ms->ms_sealed_len = NULL;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (sealed) {
			if (memcpy_s((void*)sealed, _len_sealed, __tmp_sealed, _len_sealed)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (sealed_len) {
			if (memcpy_s((void*)sealed_len, _len_sealed_len, __tmp_sealed_len, _len_sealed_len)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

