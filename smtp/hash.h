#ifndef __HASH_H
#define __HASH_H

extern char const * path;
extern char const * look;

#define SALT_LEN 16
#define SHA256_DIGEST_LENGTH 32

void create_salt(char* salt);
void add_salt(char* pass, char* salt, char* salted_pass);
void create_hash(unsigned char* plain, unsigned char* digest);
std::string hex_encode(unsigned char* hash, int len);
void write_to_file(const std::string &user, const std::string &salt, const std::string &hash);

#endif
