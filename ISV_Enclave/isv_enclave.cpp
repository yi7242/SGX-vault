#include "isv_enclave_t.h"
#include <sgx_utils.h>
#include <sgx_trts.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_attributes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "../common/debug_print.hpp"

#define MRENCLAVE 0
#define MRSIGNER 1
/* 署名・検証で使用するSPの256bit ECDSA公開鍵。
 * RAによるTLS確立前に改竄や中間者攻撃などが実行されるのを防ぐため、
 * ハードコーディングしておく必要がある。
 * RA中にランダムに生成する鍵Gbとは別物。 
 */
static const sgx_ec256_public_t service_provider_public_key = {
    {
        0x5b, 0x8f, 0x36, 0x0b, 0x05, 0x5d, 0x21, 0xa4,
        0xab, 0xb7, 0x4e, 0xd5, 0x83, 0xfc, 0xce, 0xf2,
        0x1a, 0x3d, 0x56, 0xa3, 0x96, 0x55, 0x2f, 0x94,
        0x33, 0x85, 0x35, 0x21, 0xc0, 0xad, 0xb9, 0x46
    },
    {
        0xe3, 0xb5, 0x99, 0x36, 0x58, 0x46, 0xa6, 0x87,
        0x6e, 0xf0, 0xe1, 0x12, 0x09, 0x10, 0xfa, 0xdb,
        0x9c, 0x78, 0xa0, 0x1f, 0xc3, 0xc1, 0x91, 0x8f,
        0xee, 0xb4, 0x84, 0xfc, 0x96, 0x2e, 0x22, 0x44
    }
};
sgx_status_t decrypt_message(sgx_ra_context_t ra_ctx, uint8_t *cipher, size_t cipher_len, uint8_t *iv, uint8_t *tag, uint8_t *plain) {
    ocall_print("Starting decryption...", 1);
    sgx_status_t status = SGX_SUCCESS;
    sgx_ra_key_128_t sk_key, mk_key;

    status = sgx_ra_get_keys(ra_ctx, SGX_RA_KEY_SK, &sk_key);
    status = sgx_ra_get_keys(ra_ctx, SGX_RA_KEY_MK, &mk_key);

    if(status != SGX_SUCCESS)
    {
        ocall_print("Failed to get session key.", 2);
        ocall_print_status(status);
        return status;
    }
    status = sgx_rijndael128GCM_decrypt(&sk_key, cipher,
        cipher_len, plain, iv, 12, NULL, 0, 
        (sgx_aes_gcm_128bit_tag_t*)tag);
    
    if(status != SGX_SUCCESS)
    {
        ocall_print("Failed to decrypt cipher.", 2);
        ocall_print_status(status);
        return status;
    }
    ocall_print("Decrypted message(string)", 0);
    ocall_print((const char*)plain, 0);
    ocall_print_status(status);
    return status;
}

int calc_sealed_len(int message_len)
{
	return sgx_calc_sealed_data_size(0, message_len);
}

void do_sealing(uint8_t *message, int message_len, uint8_t *sealed,
	int sealed_len, int policy)
{
	uint16_t key_policy;
	sgx_status_t status;
	sgx_attributes_t attr;
	sgx_misc_select_t misc = 0xF0000000;

	attr.flags = 0xFF0000000000000B;
	attr.xfrm = 0;

	if(policy == MRENCLAVE)
	{
		key_policy = 0x0001;
	}
	else
	{
		key_policy = 0x0002;
	}

	
	status = sgx_seal_data_ex(key_policy, attr, misc, 0, NULL,
		message_len, message, sealed_len, (sgx_sealed_data_t*)sealed);

	ocall_print_status(status);
}




int calc_unsealed_len(uint8_t *sealed, int sealed_len)
{
	return sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed);
}




sgx_status_t do_unsealing(uint8_t *sealed, int sealed_len,
	uint8_t *unsealed, int unsealed_len)
{
    ocall_print("Starting unsealing...", 1);
	sgx_status_t status;
	status = sgx_unseal_data((sgx_sealed_data_t*)sealed, NULL, 0,
		unsealed, (uint32_t*)&unsealed_len);
	ocall_print_status(status);
    if (status != SGX_SUCCESS) {
        ocall_print("Failed to unseal data", 2);
    }
    else {
        ocall_print("Unsealed data(string)", 0);
        ocall_print((const char*)unsealed, 0);
    }
    return status;
}


/* RAを初期化しsgx_ra_context_tを取得。
 * LinuxではPSEは使用不可なのでそもそもコーディングに含めない。
 * SPが複数存在する場合は、公開鍵識別用の機構を別途実装する必要がある */
sgx_status_t ecall_ra_init(sgx_ra_context_t *ra_ctx)
{
    sgx_status_t status;
    status = sgx_ra_init(&service_provider_public_key, 0, ra_ctx);

    return status;
}


/* RAの終了処理を行う */
sgx_status_t ecall_ra_close(sgx_ra_context_t ra_ctx)
{
    sgx_status_t status = sgx_ra_close(ra_ctx);
    return status;
}


sgx_status_t ecall_sample_addition(sgx_ra_context_t ra_ctx,
    uint8_t *cipher1, size_t cipher1_len, uint8_t *cipher2,
    size_t cipher2_len, uint8_t *iv, uint8_t *tag1, 
    uint8_t *tag2, uint8_t *result, size_t *result_len,
    uint8_t *iv_result, uint8_t *tag_result)
{
    sgx_status_t status = SGX_SUCCESS;
    sgx_ra_key_128_t sk_key, mk_key;

    status = sgx_ra_get_keys(ra_ctx, SGX_RA_KEY_SK, &sk_key);
    status = sgx_ra_get_keys(ra_ctx, SGX_RA_KEY_MK, &mk_key);

    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to get session key.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    if(cipher1_len > 32 || cipher2_len > 32)
    {
        const char *message = "The cipher size is too large.";
        ocall_print(message, 2);
        status = SGX_ERROR_INVALID_PARAMETER;
        return status;
    }

    /* GCMでは暗号文と平文の長さが同一 */
    uint8_t *plain_1 = new uint8_t[cipher1_len]();
    uint8_t *plain_2 = new uint8_t[cipher2_len]();

    /* GCM復号 */
    status = sgx_rijndael128GCM_decrypt(&sk_key, cipher1,
        cipher1_len, plain_1, iv, 12, NULL, 0, 
        (sgx_aes_gcm_128bit_tag_t*)tag1);
    
    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to decrypt cipher1.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    status = sgx_rijndael128GCM_decrypt(&sk_key, cipher2,
        cipher2_len, plain_2, iv, 12, NULL, 0, 
        (sgx_aes_gcm_128bit_tag_t*)tag2);
    
    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to decrypt cipher2.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    uint64_t num1 = atol((const char*)plain_1);
    uint64_t num2 = atol((const char*)plain_2);

    /* 加算を実行 */
    uint64_t total = num1 + num2;

    /* 返信用に暗号化を実施 */
    std::string total_str = std::to_string(total);
    uint8_t *total_u8 = (uint8_t*)total_str.c_str();
    
    *result_len = total_str.length();

    /* "32"はEnclave外で決め打ちで確保しているバッファ数 */
    if(*result_len > 32)
    {
        const char *message = "The result cipher size is too large.";
        ocall_print(message, 2);
        status = SGX_ERROR_INVALID_PARAMETER;
        return status;
    }

    /* RDRANDで真性乱数的にIVを生成 */
    status = sgx_read_rand(iv_result, 12);

    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to generate IV inside enclave.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    /* 計算結果をGCMで暗号化 */
    status = sgx_rijndael128GCM_encrypt(&mk_key, 
        total_u8, *result_len, result, iv_result, 12,
        NULL, 0, (sgx_aes_gcm_128bit_tag_t*)tag_result);
    
    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to encrypt result.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    delete plain_1;
    delete plain_2;

    return status;
}

sgx_status_t ecall_master_sealing(sgx_ra_context_t ra_ctx,
    uint8_t *master, size_t master_len, uint8_t *iv, uint8_t *master_tag, 
    int policy
    )
{
    sgx_status_t status = SGX_SUCCESS;
    sgx_ra_key_128_t sk_key, mk_key;

    status = sgx_ra_get_keys(ra_ctx, SGX_RA_KEY_SK, &sk_key);
    status = sgx_ra_get_keys(ra_ctx, SGX_RA_KEY_MK, &mk_key);

    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to get session key.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }
    /* GCMでは暗号文と平文の長さが同一 */
    uint8_t *master_plain = new uint8_t[master_len]();    

    /* GCM復号 */
    status = sgx_rijndael128GCM_decrypt(&sk_key, master,
        master_len, master_plain, iv, 12, NULL, 0, 
        (sgx_aes_gcm_128bit_tag_t*)master_tag);
    
    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to decrypt master.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }
    else {
        ocall_print((const char*)master_plain, 0);
        ocall_print_status(status);
        int master_char_len = strlen((char*)master_plain);
        int sealed_len = calc_sealed_len(master_char_len);
        uint8_t *sealed = new uint8_t[sealed_len];
        do_sealing(master_plain, 
				master_char_len, sealed, sealed_len, policy);
        int check;
        ocall_store_sealed_master(&check, (const char*)sealed, sealed_len);
        if (check == -1) {
            const char *message = "Failed to save from enclave";
            ocall_print(message, 2); //2はエラーログである事を表す
        }
        else {
            const char *message = "Successfully saved from enclave";
            ocall_print(message, 0);
            
            int get_sealed_len;
            ocall_get_sealed_len(&get_sealed_len, "master.dat");
            if (get_sealed_len == -1) {
                ocall_print("Failed to get sealed length from enclave", 2);
            }
            
            uint8_t* get_sealed = new uint8_t[get_sealed_len]();
            ocall_get_sealed_master(&check,get_sealed, get_sealed_len);

            uint8_t* new_get_sealed = new uint8_t[get_sealed_len]();
            memcpy(new_get_sealed, get_sealed, get_sealed_len);
            if (check == -1) {
                ocall_print("Failed to get sealed from enclave", 2);
            }
            ocall_print_binary(new_get_sealed, get_sealed_len, 0);
            int est_unsealed_len = calc_unsealed_len(new_get_sealed, get_sealed_len);
            ocall_print("est_unsealed_len", 0);
            ocall_print(std::to_string(est_unsealed_len).c_str(), 0);
            
            uint8_t* final_unsealed = new uint8_t[100]();
            do_unsealing(new_get_sealed, get_sealed_len, final_unsealed, est_unsealed_len, &check);
            ocall_print("get final unseal", 0);
            ocall_print((const char*)final_unsealed, 0);
        }
        delete master_plain;
        return status;
    }
}

