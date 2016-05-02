#include "authenc.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <string>

void RSA_keygen(EVP_PKEY** pkey) {
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_LEN*8);
    EVP_PKEY_keygen(ctx, pkey);
}

void AES_keygen(unsigned char* key, unsigned char* iv) {
    srand(time(NULL));
    for(int i = 0; i < AES_KEY_LEN; i++) {
        key[i] = rand() % 255;
    }
    for(int i = 0; i < AES_IV_LEN; i++) {
        iv[i] = rand() % 255;
    }
}

int hybrid_encrypt(unsigned char* pt, int pt_len, unsigned char** ct, int* ct_len, EVP_PKEY* pubkey, EVP_PKEY* privkey) {
    EVP_CIPHER_CTX *rsaEncryptCtx = EVP_CIPHER_CTX_new();

    unsigned char* rsa_enc = (unsigned char*)malloc(pt_len + EVP_MAX_IV_LENGTH);
    unsigned char* iv = (unsigned char*)malloc(AES_IV_LEN);
    unsigned char* tag = (unsigned char*)malloc(AES_GCM_TAG_LEN);
    unsigned char* ek = (unsigned char*)malloc(EVP_PKEY_size(pubkey));
    int ekl = 0;
    int enc_msg_len = 0;
    int block_len  = 0;

    EVP_CIPHER_CTX_ctrl(rsaEncryptCtx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, NULL);
    if(!EVP_SealInit(rsaEncryptCtx, EVP_aes_128_gcm(), &ek, &ekl, iv, &pubkey, 1)) return FAILURE;
    if(!EVP_SealUpdate(rsaEncryptCtx, rsa_enc + enc_msg_len, &block_len, pt, pt_len)) return FAILURE;
    enc_msg_len += block_len;
    if(!EVP_SealFinal(rsaEncryptCtx, rsa_enc + enc_msg_len, &block_len)) return FAILURE;
    enc_msg_len += block_len;
    EVP_CIPHER_CTX_ctrl(rsaEncryptCtx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, tag);
    EVP_CIPHER_CTX_cleanup(rsaEncryptCtx);
    EVP_CIPHER_CTX_free(rsaEncryptCtx);

    unsigned char* sig = (unsigned char*)malloc(EVP_PKEY_size(privkey));
    unsigned int sig_len;
    unsigned char* ek_iv_tag = (unsigned char*)malloc(ekl + AES_IV_LEN + AES_GCM_TAG_LEN);
    memcpy(ek_iv_tag, ek, ekl);
    memcpy(ek_iv_tag + ekl, iv, AES_IV_LEN);
    memcpy(ek_iv_tag + ekl + AES_IV_LEN, tag, AES_GCM_TAG_LEN);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    const EVP_MD *md = EVP_sha256();
    int md_len;
    if(!EVP_SignInit_ex(mdctx, md, NULL)) return FAILURE;
    if(!EVP_SignUpdate(mdctx, ek_iv_tag, ekl + AES_IV_LEN + AES_GCM_TAG_LEN)) return FAILURE;
    if(!EVP_SignFinal(mdctx, sig, &sig_len, privkey)) {
        ERR_print_errors_fp(stdout);
        return FAILURE;
    }
    EVP_MD_CTX_destroy(mdctx);

    *ct_len = enc_msg_len + ekl + AES_IV_LEN + AES_GCM_TAG_LEN + sig_len;
    *ct = (unsigned char*)malloc(*ct_len);
    memcpy(*ct, rsa_enc, enc_msg_len);
    memcpy(*ct + enc_msg_len, ek_iv_tag, ekl + AES_IV_LEN + AES_GCM_TAG_LEN);
    memcpy(*ct + enc_msg_len + ekl + AES_IV_LEN + AES_GCM_TAG_LEN, sig, sig_len);

    free(rsa_enc);
    free(ek);
    free(iv);
    free(tag);
    free(sig);
    free(ek_iv_tag);
    return SUCCESS;
}

int hybrid_decrypt(unsigned char* ct, int ct_len, unsigned char** pt, int* pt_len, EVP_PKEY* pubkey, EVP_PKEY* privkey) {
    // I think here it's safe to assume that sig_len and ek_len will be 256
    int res;
    unsigned char* ek_iv_tag = ct + ct_len - RSA_KEY_LEN - RSA_KEY_LEN - AES_IV_LEN - AES_GCM_TAG_LEN;
    unsigned char* sig = (unsigned char*)malloc(RSA_KEY_LEN);
    memcpy(sig, ct + ct_len - RSA_KEY_LEN, RSA_KEY_LEN);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    const EVP_MD *md = EVP_sha256();
    int md_len;
    if(!EVP_VerifyInit_ex(mdctx, md, NULL)) return FAILURE;
    if(!EVP_VerifyUpdate(mdctx, ek_iv_tag, RSA_KEY_LEN + AES_IV_LEN + AES_GCM_TAG_LEN)) return FAILURE;
    if((res = EVP_VerifyFinal(mdctx, sig, RSA_KEY_LEN, pubkey)) <= 0) {
        if(res < 0) {
            ERR_print_errors_fp(stdout);
            return FAILURE;
        }
        else return VERIFY_FAIL;
    }
    EVP_MD_CTX_destroy(mdctx);

    int enc_len = ct_len - RSA_KEY_LEN - RSA_KEY_LEN - AES_IV_LEN - AES_GCM_TAG_LEN;
    unsigned char* enc = ct + ct_len - enc_len;
    *pt = (unsigned char*)malloc(enc_len + EVP_MAX_IV_LENGTH);
    *pt_len = 0;
    int block_len = 0;

    unsigned char* tag = ct + ct_len - RSA_KEY_LEN - AES_GCM_TAG_LEN;
    int tag_len = AES_GCM_TAG_LEN;
    unsigned char* iv = ct + ct_len - RSA_KEY_LEN - AES_IV_LEN - AES_GCM_TAG_LEN;
    int iv_len = AES_IV_LEN;
    unsigned char* ek = ek_iv_tag;
    int ek_len = RSA_KEY_LEN;


    EVP_CIPHER_CTX* rsaDecryptCtx = EVP_CIPHER_CTX_new();

    if(!EVP_OpenInit(rsaDecryptCtx, EVP_aes_128_gcm(), ek, ek_len, iv, privkey)) return FAILURE;
    if(!EVP_OpenUpdate(rsaDecryptCtx, *pt + *pt_len, &block_len, enc, enc_len)) return FAILURE;
    *pt_len += block_len;
    if(!EVP_CIPHER_CTX_ctrl(rsaDecryptCtx, EVP_CTRL_GCM_SET_TAG, tag_len, tag)) return FAILURE;
    if(!EVP_OpenFinal(rsaDecryptCtx, *pt + *pt_len, &block_len)) {
        ERR_print_errors_fp(stdout);
        return FAILURE;
    }
    *pt_len += block_len;

    unsigned char* tmp = (unsigned char*)realloc(*pt, *pt_len);
    if(tmp) *pt = tmp;

    free(sig);
    EVP_CIPHER_CTX_free(rsaDecryptCtx);

    return SUCCESS;
}

int main() {
    EVP_PKEY *key1 = NULL;
    EVP_PKEY *key2 = NULL;
    RSA_keygen(&key1);
    RSA_keygen(&key2);

    PEM_write_PrivateKey(stdout, key1, NULL, NULL, 0, 0, NULL);
    printf("\n\n\n");
    PEM_write_PUBKEY(stdout, key2);

    unsigned char* plt = (unsigned char*)"hello world";
    unsigned char* cpt;
    int cpt_len;
    unsigned char* dec;
    int dec_len;

    int status = hybrid_encrypt(plt, strlen((char*)plt), &cpt, &cpt_len, key2, key1);
    printf("%s\n", status > 0? "SUCCESS":"FAILURE");
    status = hybrid_decrypt(cpt, cpt_len, &dec, &dec_len, key1, key2);
}
