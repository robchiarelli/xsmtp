#include <iostream>
#include <string>
#include <string.h>
#include "hash.h"
using namespace std;

void ssha(string user, string pass_str) {
    // set password length global variable
    int pass_len = pass_str.size();

    // create and fill array to store password
    char pass[pass_str.size() + 1];
    strcpy(pass, pass_str.c_str());

    // create and fill array to store salt
	string salt_temp = create_salt();
	
	char salt[SALT_LEN + 1];
    strcpy(salt, salt_temp.c_str());
    
    // create and fill array to store password + salt
    int salted_pass_len = pass_len + SALT_LEN;
    char salted_pass[salted_pass_len];
    add_salt(pass, salt, salted_pass);

    // create and fill array to store sha256 output
    unsigned char hash[SHA256_DIGEST_LENGTH];
    create_hash((unsigned char *)salted_pass, hash);

    // write username , hashed password, and salt to text file
    string salt_str((char*) salt, SALT_LEN);
    write_to_file(user, salt_str, hex_encode(hash, SHA256_DIGEST_LENGTH));
}

void register_main() {
    string user_str;
    string pass_str;

    cout << "Enter username to register: ";
    cin >> user_str;

    cout << "Enter password: ";
    cin >> pass_str;

    ssha(user_str, pass_str);
    
    cout << "\nUser registration complete.\n";
}