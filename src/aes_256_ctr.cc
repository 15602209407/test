#include "../include/aes_256_ctr.h"
#include "ippcp.h"
#include <assert.h>
#include<string.h>


/*! Helper function to compare expected and actual function return statuses and display 
 *   * an error mesage if those are different.
 *     */
static bool check_status(const char* func_name, IppStatus expected_status, IppStatus status)
{
    if (expected_status != status) {
        printf("%s: unexpected return status\n", func_name);
        printf("Expected: %s\n", ippcpGetStatusString(expected_status));
        printf("Received: %s\n", ippcpGetStatusString(status));
        return false;
    }
    return true;
}


AESCTRMODE::AESCTRMODE() : m_ctxsize(0), m_status(ippStsNoErr), m_pAES(nullptr), m_ctr_mem(nullptr),
                           m_encrypted_text(nullptr), m_decrypted_text(nullptr) {
}

AESCTRMODE::~ AESCTRMODE() {
    if (m_pAES) delete [] (Ipp8u*)m_pAES;
    if (m_encrypted_text) delete [] m_encrypted_text;
    if (m_decrypted_text) delete [] m_decrypted_text;
    if (m_ctr_mem) delete [] m_ctr_mem;
}

bool AESCTRMODE::aes_256_ctr_encryption(Ipp8u* plaintext, Ipp32u plaintext_len, Ipp8u* key256, Ipp8u key256_len, 
                                        Ipp8u* initial_counter, Ipp8u initial_counter_len) {
    assert(plaintext != nullptr);
    assert(key256 != nullptr);
    assert(initial_counter != nullptr);
    assert(key256_len == KEY_SIZE);
    assert(initial_counter_len == AES_BLOCK_SIZE);

    m_encrypted_text = new Ipp8u[plaintext_len];
    if (nullptr == m_encrypted_text) {
        printf("ERROR: Mem for m_encrypted_text allocate error !\n"); 
    }

    m_ctr_mem = new Ipp8u[initial_counter_len];
    if (nullptr == m_ctr_mem) {
        printf("ERROR: Mem for m_ctr_mem allocate error !\n"); 
    }

    /* 1. Get size needed for AES context structure */
    m_status = ippsAESGetSize(&m_ctxsize);
    if (!check_status("ippsAESGetSize", ippStsNoErr, m_status)) {
        return false;
    }
    
    /* 2. Allocate memory for AES context structure */
    m_pAES = (IppsAESSpec*)(new Ipp8u[m_ctxsize]);
    if (nullptr == m_pAES) {
       printf("ERROR: Cannot allocate memory (%d bytes) for AES context !\n", m_ctxsize);
       return false;
    }

    /* 3. Initialize AES context */
    m_status = ippsAESInit(key256, key256_len, m_pAES, m_ctxsize);
    if (!check_status("ippsAESInit", ippStsNoErr, m_status))
        return false;
    memcpy(m_ctr_mem, initial_counter, initial_counter_len);

    /* 4. Encryption */
    m_status = ippsAESEncryptCTR(plaintext, m_encrypted_text, plaintext_len, m_pAES, m_ctr_mem, COUNTER_LEN);
    if (!check_status("ippsAESEncryptCTR", ippStsNoErr, m_status))
        return false;
    
    /* 5. Remove secret and release resources */
    ippsAESInit(0, KEY_SIZE, m_pAES, m_ctxsize);
    if (m_pAES) delete [] (Ipp8u*)m_pAES;
    if (m_ctr_mem) delete [] m_ctr_mem;
    m_pAES = nullptr;
    m_ctr_mem = nullptr;
    return true;
}

bool AESCTRMODE::aes_256_ctr_decryption(Ipp8u* ciphertext, Ipp32u ciphertext_len, Ipp8u* key256, Ipp8u key256_len, 
                                        Ipp8u* initial_counter, Ipp8u initial_counter_len) {
    assert(ciphertext != nullptr);
    assert(key256 != nullptr);
    assert(initial_counter != nullptr);
    assert(key256_len == KEY_SIZE);
    assert(initial_counter_len == AES_BLOCK_SIZE);

    m_decrypted_text = new Ipp8u[ciphertext_len];
    if (nullptr == m_decrypted_text) {
       printf("ERROR: Mem for m_decrypted_text allocate error !\n"); 
       return false;
    }
    m_ctr_mem = new Ipp8u[initial_counter_len];
    if (nullptr == m_ctr_mem) {
        printf("ERROR: Mem for m_ctr_mem allocate error !\n");
        return false;
    }

    /* 1. Get size needed for AES context structure */
    m_status = ippsAESGetSize(&m_ctxsize);
    if (!check_status("ippsAESGetSize", ippStsNoErr, m_status)) {
        return false;
    }

    /* 2. Allocate memory for AES context structure */
    m_pAES = (IppsAESSpec*)(new Ipp8u[m_ctxsize]);
    if (nullptr == m_pAES) {
       printf("ERROR: Cannot allocate memory (%d bytes) for AES context !\n", m_ctxsize);
       return false;
    }

    /* 3. Initialize AES context */
    m_status = ippsAESInit(key256, key256_len, m_pAES, m_ctxsize);
    if (!check_status("ippsAESInit", ippStsNoErr, m_status))
        return false;
    memcpy(m_ctr_mem, initial_counter, initial_counter_len);

    /* 4. Decryption */
    m_status = ippsAESDecryptCTR(ciphertext, m_decrypted_text, ciphertext_len, m_pAES, m_ctr_mem, COUNTER_LEN);
    if (!check_status("ippsAESEncryptCTR", ippStsNoErr, m_status))
        return false;

    /* 5. Remove secret and release resources */
    ippsAESInit(0, KEY_SIZE, m_pAES, m_ctxsize);
    if (m_pAES) delete [] (Ipp8u*)m_pAES;
    if (m_ctr_mem) delete [] m_ctr_mem;
    m_pAES = nullptr;
    m_ctr_mem = nullptr;
    return true;
}
void AESCTRMODE::aes_256_ctr_enc_dec_test(Ipp8u* plaintext, Ipp32u plaintext_len, Ipp8u* key256, Ipp8u key256_len, 
                                        Ipp8u* initial_counter, Ipp8u initial_counter_len) {
    printf("Message to be encrypted : %s\n",plaintext);
    aes_256_ctr_encryption(plaintext, plaintext_len, key256, key256_len, initial_counter, initial_counter_len);
    assert(m_encrypted_text != nullptr);
    aes_256_ctr_decryption(m_encrypted_text, plaintext_len, key256, key256_len, initial_counter, initial_counter_len);
    printf("Afte decrypted, Message is : %s\n", m_decrypted_text);
}
/*! Check for encryted message, this function should be called after function aes_256_ctr_encryption */
bool AESCTRMODE::check_encrypted(Ipp8u* ciphertext, Ipp32u ciphertext_len) {
    assert(m_encrypted_text != nullptr);
    assert(ciphertext != nullptr);
    return memcmp(m_encrypted_text, ciphertext, ciphertext_len) == 0 ? true : false;
}

/*! Check for decryted message, this function should be called after function aes_256_ctr_decryption */
bool AESCTRMODE::check_decrypted(Ipp8u* plaintext, Ipp32u plaintext_len) {
    assert(m_decrypted_text != nullptr);
    assert(plaintext != nullptr);
    return memcmp(m_decrypted_text, plaintext, plaintext_len) == 0 ? true : false;
}
/* Check for both encryted and decryted message, this function should be called after function after aes_256_ctr_encryption and aes_256_ctr_decryption */
void AESCTRMODE::is_success(Ipp8u* plaintext, Ipp8u* ciphertext, Ipp32u text_len) {
    if(check_encrypted(ciphertext, text_len) && check_decrypted(plaintext, text_len)) {
        printf("SUSSES: The process of both aes_256_ctr_encryption and aes_256_ctr_decryption are right !\n");
        return;
    }
    printf("ERROR: Something goes wrong in aes_256_ctr_encryption or aes_256_ctr_decryption !\n");
}
