#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <cstring>
#include "hash.h"

using namespace std;

char const * dir = "data/users.txt";

void validate_user(string user, string pass_str) {
	ifstream file(dir);
	string line;
	string salt_str;
	bool user_flag = false;
	while(getline(file, line)) {
		size_t first = line.find(',');
		string file_user = line.substr(0,first);
		if (file_user == user) {
			user_flag = true;
			size_t second = line.find(',', first + 1);
			salt_str = line.substr(first + 1, second - first - 1);
			break;
		}
	}
	if (!user_flag) {
		cout << "That username does not exist.\n";		
		return;
	}
	
	char pass[pass_str.size() + 1];
    strcpy(pass, pass_str.c_str());
    
    char salt[SALT_LEN];
    for (int i = 0; i < SALT_LEN; i++) salt[i] = salt_str[i];
	
	char salted_pass[pass_str.size() + SALT_LEN];
	add_salt(pass, salt, salted_pass);
	cout << salted_pass << endl;
	
    // create and fill array to store sha256 output
    unsigned char hash[SHA256_DIGEST_LENGTH];
    create_hash((unsigned char *)salted_pass, hash);
    
    cout << hex_encode(hash, SHA256_DIGEST_LENGTH) << endl;

	// check users.txt fo
}

int main() {
	string user;
	string pass;
	cout << "Enter your username: ";
	cin >> user;
	cout << "Enter your password: ";
	cin >> pass;
	validate_user(user, pass);
}
