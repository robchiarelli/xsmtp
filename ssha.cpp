#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string.h>

using namespace std;

char const * path = "data/users.txt";
const int salt_len = 16;
int pass_len = 0;
const string lookup = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

char* create_salt(char* salt) {
    // create randomized string of characters of length salt_len
    srand(time(NULL));
    for (int i = 0; i < salt_len; i++) {
        salt[i] = lookup[rand() % (lookup.size() - 1)];
    }
}

char* add_salt(char* pass, char* salt, char* salted_pass) {
    // combine original password and salt
    // strcat was causing issues so i wrote it myself
    for (int i = 0; i < pass_len; i++) {
        salted_pass[i] = pass[i];
    }
    for (int i = pass_len; i < pass_len + salt_len; i++) {
        salted_pass[i] = salt[i - pass_len];
    }
}

void create_hash(unsigned char* plain, unsigned char* digest, int len) {
    // SHA256_CTX context;
    // SHA256_Init(&context);
    // SHA256_Update(&context, pass_plain, len);
    // SHA256_Final(pass_enc, &context);
    // openssl docs recommend to use the below functions instead of the SHA256 functions directly.
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    const EVP_MD *md = EVP_sha256();
    int md_len;
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, plain, len);
    EVP_DigestFinal_ex(mdctx, digest, NULL);
    EVP_MD_CTX_destroy(mdctx);
}

void write_to_file(string user, string salt, string hash) {
    ofstream file;
    file.open(path, ios::app);
    file << user << "," << salt << "," << hash << endl;
    file.close();
}

string hex_encode(unsigned char* hash, int len) {
    char tmp[len*2];
    for(int i = 0, j = 0; i < len; i++, j+=2) {
        sprintf(tmp + j, "%02x", hash[i]);
    }
    return string(tmp);
}

void ssha(string user, string pass_str) {
    // set password length global variable
    pass_len = pass_str.size();

    // create and fill array to store password
    char pass[pass_str.size()];
    for (int i = 0; i < pass_str.size(); i++) { pass[i] = pass_str[i]; }

    // create and fill array to store salt
    char salt[salt_len];
    create_salt(salt);

    // create and fill array to store password + salt
    int salted_pass_len = pass_len + salt_len;
    char salted_pass[salted_pass_len];
    add_salt(pass, salt, salted_pass);

    // create and fill array to store sha256 output
    unsigned char hash[SHA256_DIGEST_LENGTH];
    create_hash((unsigned char *)salted_pass, hash, pass_len + salt_len);

    // write username , hashed password, and salt to text file
    string salt_str((char*) salt, salt_len);
    write_to_file(user, salt_str, hex_encode(hash, SHA256_DIGEST_LENGTH));
}

int main() {
    //string user = "robobert"
    //string pass_str = "password";
    string user;
    string pass_str;

    cout << "Enter username to register: ";
    cin >> user;

    cout << "Enter password: ";
    cin >> pass_str;

    ssha(user, pass_str);

    cout << "User registration complete.\n";

    return 0;
}
