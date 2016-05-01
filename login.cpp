#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <cstring>
#include "hash.h"

#include "login.h"
using namespace std;

char const * dir = "data/users.txt";

//void validate_user(string user, string pass_str) {
bool validate_user() {
	string user;
	string pass_str;
	cout << "Enter your username: ";
	cin >> user;
	cout << "Enter your password: ";
	cin >> pass_str;
	
	ifstream file(dir);
	string line;
	string salt_str;
	string hash_str;
	bool user_flag = false;
	while(getline(file, line)) {
		size_t first = line.find(',');
		string file_user = line.substr(0,first);
		if (file_user == user) {
			user_flag = true;
			size_t second = line.find(',', first + 1);
			salt_str = line.substr(first + 1, second - first - 1);
			hash_str = line.substr(second + 1, line.size() - 1);
			break;
		}
	}
	if (!user_flag) {
		cout << "That username does not exist.\n";		
		return false;
	}
	
	char pass[pass_str.size() + 1];
    strcpy(pass, pass_str.c_str());
    
    char salt[SALT_LEN + 1];
    strcpy(salt, salt_str.c_str());
	
	char salted_pass[pass_str.size() + SALT_LEN];
	add_salt(pass, salt, salted_pass);
	
    // create and fill array to store sha256 output
    unsigned char hash[SHA256_DIGEST_LENGTH];
    create_hash((unsigned char *)salted_pass, hash);

	if (hash_str == hex_encode(hash, SHA256_DIGEST_LENGTH)) return true;
	else return false;
}
/*
int main() {
	string user;
	string pass;
	cout << "Enter your username: ";
	cin >> user;
	cout << "Enter your password: ";
	cin >> pass;
	validate_user(user, pass);
}
*/
