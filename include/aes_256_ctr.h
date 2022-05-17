#pragma once
#include <stdio.h>
#include "ippcp.h"
/*! Helper function to compare expected and actual function return statuses and display 
 *  an error mesage if those are different.
 */
static bool check_status(const char* func_name, IppStatus expected_status, IppStatus status);

/*! AES-256, use CTR mode.*/
class  AESCTRMODE
{
private:
    /*! Size for AES context structure */
    int m_ctxsize;
    /*! Pointer to AES context structure */
    IppsAESSpec* m_pAES;
    /*! Error status */
    IppStatus m_status;
    /*! AES block size in bytes */
    static const int AES_BLOCK_SIZE = 16;
    /*! Key size in bytes */
    static const int KEY_SIZE = 32;
    /*！Length of changeable bits in a counter (can be value starting from 1 till block size 128) */
    static const Ipp32u COUNTER_LEN = 64;
    /*！Memony for counter */
    Ipp8u* m_ctr_mem;
    /*! Pointer to encrypted plain text*/
    Ipp8u* m_encrypted_text;
    /*! Pointer to encrypted plain text*/
    Ipp8u* m_decrypted_text;
                                                
public:
    AESCTRMODE();
    ~ AESCTRMODE();
    bool aes_256_ctr_encryption(Ipp8u* plaintext, Ipp32u plaintext_len, Ipp8u* key256, Ipp8u key256_len, 
                                Ipp8u* initial_counter, Ipp8u initial_counter_len);
    bool aes_256_ctr_decryption(Ipp8u* ciphertext, Ipp32u ciphertext_len, Ipp8u* key256, Ipp8u key256_len,
                                Ipp8u* initial_counter, Ipp8u initial_counter_len);
    /*! This function used just for test, Demo 2 will call this */
    void aes_256_ctr_enc_dec_test(Ipp8u* plaintext, Ipp32u plaintext_len,Ipp8u* key256, Ipp8u key256_len, 
                                  Ipp8u* initial_counter, Ipp8u initial_counter_len);
    bool check_encrypted(Ipp8u* ciphertext, Ipp32u ciphertext_len);
    bool check_decrypted(Ipp8u* plaintext, Ipp32u plaintext_len);

    void is_success(Ipp8u* plaintext, Ipp8u* ciphertext, Ipp32u text_len);
};
