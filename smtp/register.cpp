#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>

#include "hash.h"
using namespace std;

void send_to_server(string user, string salt, string hash) {
    int sockfd, portno, n;
    char* hostname = "localhost";
    portno = 60085;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    server = gethostbyname(hostname);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR connecting");
    }
    string command = "python ../hybrid.py register "+user+","+"salt"+","+hash;
    system(command.c_str());
    ifstream ifs("reg");
    stringstream buffer;
    buffer << ifs.rdbuf();
    string b = buffer.str();
    n = write(sockfd, buffer.str().c_str(), buffer.str().size());
    close(sockfd);
}

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
    send_to_server(user, salt_str, hex_encode(hash, SHA256_DIGEST_LENGTH));

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
