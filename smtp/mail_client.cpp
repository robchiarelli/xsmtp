#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <iostream>
#include <fstream>
#include <sstream>
#include <Python.h>

using namespace std;

char* message_path = "/home/rob/xsmtp/smtp/message.txt";
char* py_path = "/home/rob/xsmtp/smtp/script.py"

string read_from_file() {
	ifstream file(message_path);
	string line;
	
	//while (getline(file, line)) cout << line << endl;
	stringstream buffer;
	buffer << file.rdbuf();
	string message = buffer.str();
	file.close();
	
	return message;
}

void send_to_encrypt(string message) {
	string command = "python " + py_path + " encrypt " + message;
	system(command.c_str());
}

int mail_client(char* hostname, int portno, string user) {
	int sock, n;
	string mode;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    char buffer[256];
    if (portno == 25) mode = "smtp";
    else if (portno == 110) mode = "localhost";
    
    // set up the socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) 
        cout << "ERROR opening socket\n";
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    
	// connect to the socket
	bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sock,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        cout << "ERROR connecting\n";
    //printf("Please enter the message: ");
    
    // smtp
    if (portno == 25) { 
        
    	// send and receive for the HELO command
    	bzero(buffer, 256);
    	string command = "HELO\n";
    	for (int i = 0; i < command.size(); i++) buffer[i] = command[i];
    	n = write(sock, buffer, strlen(buffer));
    	if (n < 0) 
    		cout << "ERROR writing to socket\n";
    	bzero(buffer,256);
    	n = read(sock, buffer, 255);
    	if (n < 0) 
    		cout << "ERROR reading from socket\n";
    	printf("%s\n", buffer);
    
    	// send and receive for the MAIL command
    	bzero(buffer, 256);
    	command = "MAIL FROM:<" + user + ">\n";
    	for (int i = 0; i < command.size(); i++) buffer[i] = command[i];
    	n = write(sock, buffer, strlen(buffer));
    	if (n < 0) 
    		cout << "ERROR writing to socket\n";
    	bzero(buffer,256);
    	n = read(sock, buffer, 255);
    	if (n < 0) 
        	cout << "ERROR reading from socket\n";
    	printf("%s\n", buffer);
    	
    	    
    	// send and receive for the RCPT command
    	bzero(buffer, 256);
    	cout << "Enter your recipient's email address: ";
    	string temp;
    	cin >> temp;
    	string rcpt = "RCPT TO:<" + temp + ">\n";
    	for (int i = 0; i < rcpt.size(); i++) buffer[i] = rcpt[i];
    	n = write(sock, buffer, strlen(buffer));
    	if (n < 0) 
    		cout << "ERROR writing to socket\n";
    	bzero(buffer,256);
    	n = read(sock, buffer, 255);
    	if (n < 0) 
        	cout << "ERROR reading from socket\n";
    	printf("%s\n", buffer);
    	    
    	// send and receive for the DATA command
    	bzero(buffer, 256);
    	command = "DATA\n";
    	for (int i = 0; i < command.size(); i++) buffer[i] = command[i];
    	n = write(sock, buffer, strlen(buffer));
    	if (n < 0) 
    		cout << "ERROR writing to socket\n";
    	bzero(buffer,256);
    	n = read(sock, buffer, 255);
    	if (n < 0) 
        	cout << "ERROR reading from socket\n";
    	printf("%s\n", buffer);
    	
    	bzero(buffer, 256);
    	cout << "Enter your message: ";
    	ws(cin);
    	getline(cin, temp);
    	
    	// send the plaintext message to be encrypted
    	send_to_encrypt(temp);
    	
    	// read and send the now encrypted message
    	string message = read_from_file();
    	command = message + "<CR><LF>";
    	for (int i = 0; i < command.size(); i++) buffer[i] = command[i];
    	n = write(sock, buffer, strlen(buffer));
    	if (n < 0) 
    		cout << "ERROR writing to socket\n";
    	bzero(buffer,256);
    	n = read(sock, buffer, 255);
    	if (n < 0) 
        	cout << "ERROR reading from socket\n";
    	printf("%s\n", buffer);
    	
    	bzero(buffer, 256);
    	command = "QUIT\n";
    	for (int i = 0; i < command.size(); i++) buffer[i] = command[i];
    	n = write(sock, buffer, strlen(buffer));
    	if (n < 0) 
    		cout << "ERROR writing to socket\n";
    	bzero(buffer,256);
    	n = read(sock, buffer, 255);
    	if (n < 0) 
        	cout << "ERROR reading from socket\n";
    	printf("%s\n", buffer);
    }
    // xpop3
    else if (portno == 110) {
    
    	// send and receive for the USER command
    	bzero(buffer, 256);
    	string command = "USER " + user + "\n";
    	for (int i = 0; i < command.size(); i++) buffer[i] = command[i];
    	n = write(sock, buffer, strlen(buffer));
    	if (n < 0) 
    		cout << "ERROR writing to socket\n";
    	bzero(buffer,256);
    	n = read(sock, buffer, 255);
    	if (n < 0) 
        	cout << "ERROR reading from socket\n";
    	printf("%s\n", buffer);
    	    
    	// send and receive for the PASS command
    	bzero(buffer, 256);
    	command = "PASS password\n";
    	for (int i = 0; i < command.size(); i++) buffer[i] = command[i];
    	n = write(sock, buffer, strlen(buffer));
    	if (n < 0) 
    		cout << "ERROR writing to socket\n";
    	bzero(buffer,256);
    	n = read(sock, buffer, 255);
    	if (n < 0) 
        	cout << "ERROR reading from socket\n";
    	printf("%s\n", buffer);
    	
    	    
    	// send and receive for the LIST command
    	bzero(buffer, 256);
    	command = "LIST\n";
    	for (int i = 0; i < command.size(); i++) buffer[i] = command[i];
    	n = write(sock, buffer, strlen(buffer));
    	if (n < 0) 
    		cout << "ERROR writing to socket\n";
    	bzero(buffer,256);
    	n = read(sock, buffer, 255);
    	if (n < 0) 
        	cout << "ERROR reading from socket\n";
    	printf("%s\n", buffer);
    	    
    	// send and receive for the QUIT command
    	bzero(buffer, 256);
    	command = "QUIT\n";
    	for (int i = 0; i < command.size(); i++) buffer[i] = command[i];
    	n = write(sock, buffer, strlen(buffer));
    	if (n < 0) 
    		cout << "ERROR writing to socket\n";
    	bzero(buffer,256);
    	n = read(sock, buffer, 255);
    	if (n < 0) 
        	cout << "ERROR reading from socket\n";
    	printf("%s\n", buffer);
    	
    	cin.get();
    	
    }
    close(sock);
    return 0;
	
}
