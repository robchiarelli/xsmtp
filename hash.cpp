//#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string.h>

#include "hash.h"
using namespace std;

char const * path = "data/users.txt";
char const * alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

void create_salt(char* salt) {
    // create randomized string of characters of length SALT_LEN
    srand(time(NULL));
    for (int i = 0; i < SALT_LEN; i++) {
        salt[i] = alphanum[rand() % (strlen(alphanum))];
    }
}

void add_salt(char* pass, char* salt, char* salted_pass) {
    // combine original password and salt
    strcpy(salted_pass, pass);
    strcat(salted_pass, salt);
}

void create_hash(unsigned char* plain, unsigned char* digest) {
    // SHA256_CTX context;
    // SHA256_Init(&context);
    // SHA256_Update(&context, pass_plain, len);
    // SHA256_Final(pass_enc, &context);
    // openssl docs recommend to use the below functions instead of the SHA256 functions directly.
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    const EVP_MD *md = EVP_sha256();
    int md_len;
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, plain, strlen((char*)plain));
    EVP_DigestFinal_ex(mdctx, digest, NULL);
    EVP_MD_CTX_destroy(mdctx);
}

string hex_encode(unsigned char* hash, int len) {
    char tmp[len*2];
    for(int i = 0, j = 0; i < len; i++, j+=2) {
        sprintf(tmp + j, "%02x", hash[i]);
    }
    return string(tmp);
}

void write_to_file(const std::string &user, const std::string &salt, const std::string &hash) {
    ofstream file;
    file.open(path, ios::app);
    file << user << "," << salt << "," << hash << endl;
    file.close();
}

