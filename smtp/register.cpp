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
	cout << salt << endl;

    // create and fill array to store password + salt
    int salted_pass_len = pass_len + SALT_LEN;
    char salted_pass[salted_pass_len];
    add_salt(pass, salt, salted_pass);
    
    cout << salted_pass << endl;

    // create and fill array to store sha256 output
    unsigned char hash[SHA256_DIGEST_LENGTH];
    create_hash((unsigned char *)salted_pass, hash);

    // write username , hashed password, and salt to text file
    string salt_str((char*) salt, SALT_LEN);
    write_to_file(user, salt_str, hex_encode(hash, SHA256_DIGEST_LENGTH));
}

void register_main() {
    //string user = "robobert"
    //string pass_str = "password";
    string user_str;
    string pass_str;
    //char user[256];
    //char pass[256];

    cout << "Enter username to register: ";
    cin >> user_str;

    cout << "Enter password: ";
    cin >> pass_str;
    
    //int user_len = strlen(user);
    //int pass_len = strlen(pass);

	//char user_char[user_len];
	//char pass_char[pass_len];
	//for (int i = 0; i < user_len; i++) user_char[i] = user[i];
	//for (int i = 0; i < pass_len; i++) pass_char[i] = pass[i];
	
	//string user_str(user_char);
	//string pass_str(pass_char);

    ssha(user_str, pass_str);
    
    cout << "\nUser registration complete.\n";

    //return user;
}
