#include "../include/aes_256_ctr.h"
#include <string.h>
#include "ippcp.h"
#include <assert.h>
#include <stdio.h>

int main(void)
{
    /*! message to be encrypted */
    /*! Plain text */
    Ipp8u plain_text[16] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
    0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    /*! Cipher text */
    Ipp8u cipher_text[16] = {
    0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,
    0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28 
    };
    /*! 256-bit secret key */
    Ipp8u key256[32] = {
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
    0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
    0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
    0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    
    /*! Initial counter for CTR mode.
    *  Size of counter for AES-CTR shall be equal to the size of AES block (16 bytes).
    */
    Ipp8u initial_counter[16] = {
    0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
    0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };
    printf("*************************Demo 1*************************\n");
    AESCTRMODE aes256_demo1;
    if (!aes256_demo1.aes_256_ctr_encryption(plain_text, sizeof(plain_text), key256, sizeof(key256), initial_counter, sizeof(initial_counter))) {
       printf("\tERROR: Something goes wrong in function aes_256_ctr_encryption !\n");
    } 
    if (aes256_demo1.check_encrypted(cipher_text,sizeof(cipher_text))) {
       printf("\tSUCCESS: message is encrypted !\n");
    } else {
       printf("\tERROR: Something goes wrong in encryption process !\n");
    }
    
    if (!aes256_demo1.aes_256_ctr_decryption(cipher_text, sizeof(cipher_text), key256, sizeof(key256), initial_counter, sizeof(initial_counter))) {
       printf("\tERROR: Something goes wrong in function aes_256_ctr_decryption !\n");
    } 
    if (aes256_demo1.check_encrypted(cipher_text,sizeof(cipher_text))) {
       printf("\tSUCCESS: message is decrypted !\n");
    } else {
       printf("\tERROR: Something goes wrong in decryption process !\n");
   }
   printf("*************************Demo 2*************************\n");
   AESCTRMODE aes256_demo2;
   Ipp8u msg[] = "the quick brown fox jumps over the lazy dog";
   aes256_demo2.aes_256_ctr_enc_dec_test(msg, sizeof(msg), key256, sizeof(key256), initial_counter, sizeof(initial_counter));
   return 0;
}
