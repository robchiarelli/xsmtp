#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string.h>

using namespace std;

char* path = "data/users.txt";
const int salt_len = 16;
int pass_len = 0;
int key_len = 2048;
int pub_exp = 17;
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

void create_hash(unsigned char* pass_plain, unsigned char* pass_enc, int len) {
	SHA256_CTX context;
	
	SHA256_Init(&context);
	SHA256_Update(&context, pass_plain, len);
	SHA256_Final(pass_enc, &context);
}

void generate_pub_key(RSA* keypair, BIO* pub, char* pub_key) {
    PEM_write_bio_RSAPublicKey(pub, keypair);

    size_t pub_len = BIO_pending(pub);

    pub_key = (char*)malloc(pub_len + 1);

    BIO_read(pub, pub_key, pub_len);

    pub_key[pub_len] = '\0';
}

void write_to_file(string user,  unsigned char* pass, 
				   char* salt, char* key) {
	ofstream file;
	file.open(path, ios::app);
	file << user << " " 
		 << pass << " " 
		 << salt << " " 
		 << key << endl;
	file.close();
}

void ssha(string user, string pass_str) {
	
	// set password length global variable
	pass_len = pass_str.size();
	
	// create and fill array to store password
	char pass[pass_str.size()];
	for (int i = 0; i < pass_str.size(); i++) { pass[i] = pass_str[i]; }
	
	// create and fill array to store salt
	char salt[salt_len] = " ";
	create_salt(salt);
	
	// create and fill array to store password + salt
	char salted_pass[pass_len + salt_len];
	add_salt(pass, salt, salted_pass);

	cout << salt << endl;
	
	// copy signed password array into unsigned array for use by sha256
	unsigned char pass_plain[pass_len + salt_len];
	for (int i = 0; i < pass_len + salt_len; i++) { pass_plain[i] = salted_pass[i]; }
	
	cout << salt << endl;

	// create and fill array to store sha256 output
	unsigned char pass_enc[SHA256_DIGEST_LENGTH];
	create_hash(pass_plain, pass_enc, sizeof(salted_pass));

	cout << salt << endl;

	RSA* keypair = RSA_generate_key(key_len, pub_exp, NULL, NULL);
	BIO* pub = BIO_new(BIO_s_mem());
	char* pub_key;
	generate_pub_key(keypair, pub, pub_key);
	
	// write username , hashed password, and salt to text file
	cout << salt << endl;
	write_to_file(user, pass_enc, salt, pub_key);
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
