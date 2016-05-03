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
#include <assert.h>
#include <iostream>
using namespace std;

string hex_encode(unsigned char* hash, int len) {
    char tmp[len*2];
    for(int i = 0, j = 0; i < len; i++, j+=2) {
        sprintf(tmp + j, "%02x", hash[i]);
    }
    return string(tmp);
}

void RSA_keygen(EVP_PKEY** pkey) {
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_LEN*8);
    EVP_PKEY_keygen(ctx, pkey);
}

int rsaEncrypt(const unsigned char *msg, size_t msgLen, unsigned char **encMsg, unsigned char **ek, size_t *ekl, unsigned char **iv, size_t *ivl, EVP_PKEY* key) {
    EVP_CIPHER_CTX* rsaEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(rsaEncryptCtx);
    size_t encMsgLen = 0;
    size_t blockLen  = 0;

    *ek = (unsigned char*)malloc(EVP_PKEY_size(key));
    *iv = (unsigned char*)malloc(EVP_MAX_IV_LENGTH);
    if(*ek == NULL || *iv == NULL) return FAILURE;
    *ivl = EVP_MAX_IV_LENGTH;

    *encMsg = (unsigned char*)malloc(msgLen + EVP_MAX_IV_LENGTH);
    if(encMsg == NULL) return FAILURE;

    if(!EVP_SealInit(rsaEncryptCtx, EVP_aes_256_gcm(), ek, (int*)ekl, *iv, &key, 1)) {
        return FAILURE;
    }

    if(!EVP_SealUpdate(rsaEncryptCtx, *encMsg + encMsgLen, (int*)&blockLen, (const unsigned char*)msg, (int)msgLen)) {
        return FAILURE;
    }
    encMsgLen += blockLen;

    if(!EVP_SealFinal(rsaEncryptCtx, *encMsg + encMsgLen, (int*)&blockLen)) {
        ERR_print_errors_fp(stdout);
        return FAILURE;
    }
    encMsgLen += blockLen;
    EVP_CIPHER_CTX_cleanup(rsaEncryptCtx);
    free(rsaEncryptCtx);
    return (int)encMsgLen;
}

int rsaDecrypt(unsigned char *encMsg, size_t encMsgLen, unsigned char *ek, size_t ekl, unsigned char *iv, size_t ivl, unsigned char **decMsg, EVP_PKEY* key) {
    EVP_CIPHER_CTX* rsaDecryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(rsaDecryptCtx);

    size_t decLen   = 0;
    size_t blockLen = 0;

    *decMsg = (unsigned char*)malloc(encMsgLen + ivl);
    if(decMsg == NULL) return FAILURE;
    if(!EVP_OpenInit(rsaDecryptCtx, EVP_aes_256_gcm(), ek, ekl, iv, key)) {
        ERR_print_errors_fp(stdout);
        return FAILURE;
    }

    if(!EVP_OpenUpdate(rsaDecryptCtx, (unsigned char*)*decMsg + decLen, (int*)&blockLen, encMsg, (int)encMsgLen)) {
        ERR_print_errors_fp(stdout);
        return FAILURE;
    }
    decLen += blockLen;

    if(!EVP_OpenFinal(rsaDecryptCtx, (unsigned char*)*decMsg + decLen, (int*)&blockLen)) {
        ERR_print_errors_fp(stdout);
        return FAILURE;
    }
    decLen += blockLen;

    EVP_CIPHER_CTX_cleanup(rsaDecryptCtx);
    free(rsaDecryptCtx);
    return (int)decLen;
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
    unsigned char* ek;
    int ekl;
    unsigned char* iv;
    int ivl;
    *ct_len = rsaEncrypt(pt, pt_len, ct, &ek, (size_t*)&ekl, &iv, (size_t*)&ivl, pubkey);
    if(*ct_len == FAILURE) return FAILURE;
    unsigned char* sig = (unsigned char*)malloc(EVP_PKEY_size(privkey));
    unsigned int sig_len;
    unsigned char* ek_iv_ct = (unsigned char*)malloc(ekl + ivl + *ct_len);
    memcpy(ek_iv_ct, ek, ekl);
    memcpy(ek_iv_ct + ekl, iv, ivl);
    memcpy(ek_iv_ct + ekl + ivl, *ct, *ct_len);

    EVP_MD_CTX *mdctx = (EVP_MD_CTX*)malloc(sizeof(EVP_MD_CTX));
    EVP_MD_CTX_init(mdctx);
    const EVP_MD *md = EVP_sha256();
    if(!EVP_SignInit_ex(mdctx, md, NULL)) return FAILURE;
    if(!EVP_SignUpdate(mdctx, ek_iv_ct, ekl + ivl + *ct_len)) return FAILURE;
    if(!EVP_SignFinal(mdctx, sig, &sig_len, privkey)) {
        ERR_print_errors_fp(stdout);
        return FAILURE;
    }
    EVP_MD_CTX_cleanup(mdctx);
    free(mdctx);

    free(*ct);
    *ct = (unsigned char*)malloc(sig_len + ekl + ivl + *ct_len);
    memcpy(*ct, sig, sig_len);
    memcpy(*ct + sig_len, ek_iv_ct, ekl + ivl + *ct_len);
    *ct_len = *ct_len + ekl + ivl + sig_len;

    cout << "pt: " << hex_encode(pt, pt_len) << endl;
    cout << "ct: " << hex_encode(*ct, *ct_len) << endl;
    cout << "ek: " << hex_encode(ek, ekl) << endl;
    cout << "iv: " << hex_encode(iv, ivl) << endl;
    cout << "sig: " << hex_encode(sig, sig_len) << endl;


    free(ek);
    free(iv);
    free(sig);
    free(ek_iv_ct);
    return SUCCESS;
}

int hybrid_decrypt(unsigned char* ct, int ct_len, unsigned char** pt, int* pt_len, EVP_PKEY* pubkey, EVP_PKEY* privkey) {
    // I think here it's safe to assume that sig_len and ek_len will be 256
    int res;
    int sig_len = EVP_PKEY_size(privkey);
    unsigned char* sig = (unsigned char*)malloc(sig_len);
    memcpy(sig, ct, sig_len);

    EVP_MD_CTX *mdctx = (EVP_MD_CTX*)malloc(sizeof(EVP_MD_CTX));
    EVP_MD_CTX_init(mdctx);
    const EVP_MD *md = EVP_sha256();
    if(!EVP_VerifyInit_ex(mdctx, md, NULL)) return FAILURE;
    if(!EVP_VerifyUpdate(mdctx, ct + sig_len, ct_len - sig_len)) return FAILURE;
    if((res = EVP_VerifyFinal(mdctx, sig, sig_len, pubkey)) <= 0) {
        if(res < 0) {
            ERR_print_errors_fp(stdout);
            return FAILURE;
        }
        else return VERIFY_FAIL;
    }
    EVP_MD_CTX_cleanup(mdctx);
    free(mdctx);

    int ekl = EVP_PKEY_size(pubkey);
    unsigned char* ek = (unsigned char*)malloc(ekl);
    memcpy(ek, ct + sig_len, ekl);

    int ivl = AES_IV_LEN;
    unsigned char* iv = (unsigned char*)malloc(ivl);
    memcpy(iv, ct + ct_len + ekl, AES_IV_LEN);

    int enc_len = ct_len - (sig_len + ekl + ivl);
    unsigned char* enc = (unsigned char*)malloc(enc_len);
    memcpy(enc, ct + ct_len + ekl + ivl, enc_len);

    unsigned char* dec;
    int dec_len;
    dec_len = rsaDecrypt(enc, enc_len, ek, ekl, iv, ivl, &dec, privkey);
    *pt = dec;
    *pt_len = dec_len;

    cout << "pt: " << hex_encode(*pt, *pt_len) << endl;
    cout << "ct: " << hex_encode(ct, ct_len) << endl;
    cout << "ek: " << hex_encode(ek, ekl) << endl;
    cout << "iv: " << hex_encode(iv, ivl) << endl;
    cout << "sig: " << hex_encode(sig, sig_len) << endl;

    free(sig);
    free(ek);
    free(iv);
    free(enc);
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

    unsigned char* plt = (unsigned char*)"hello world i am very angry right now. blah blah blah.";
    unsigned char* cpt;
    int cpt_len;
    unsigned char* ek;
    int ekl;
    unsigned char* iv;
    int ivl;
    unsigned char* dec;
    int dec_len;

    //cpt_len = rsaEncrypt(plt, strlen((char*)plt), &cpt, &ek, (size_t*)&ekl, &iv, (size_t*)&ivl, key1);
    //cout << hex_encode(cpt, cpt_len) << endl;
    //dec_len = rsaDecrypt(cpt, cpt_len, ek, (size_t)ekl, iv, (size_t)ivl, &dec, key1);

    int status = hybrid_encrypt(plt, strlen((char*)plt) + 1, &cpt, &cpt_len, key2, key1);
    printf("%s\n", status > 0? "SUCCESS":"FAILURE");
    status = hybrid_decrypt(cpt, cpt_len, &dec, &dec_len, key1, key2);
    printf("%s", dec);
}
