#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <iostream>

using namespace std;

int main(int argc, char *argv[]) {
	int sock, portno, n;
	string mode;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    char buffer[256];
    if (argc < 3) {
       fprintf(stderr,"usage %s hostname port\n", argv[0]);
       exit(0);
    }
    portno = atoi(argv[2]);
    if (portno == 25) mode = "smtp";
    else if (portno == 110) mode = "localhost";
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) 
        cout << "ERROR opening socket\n";
    server = gethostbyname(argv[1]);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    string buf;
    cin >> buf;
	
	bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sock,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        cout << "ERROR connecting\n";
    printf("Please enter the message: ");
    bzero(buffer, 256);
    fgets(buffer, 255, stdin);
    n = write(sock,buffer,strlen(buffer));
    if (n < 0) 
         cout << "ERROR writing to socket\n";
    bzero(buffer,256);
    n = read(sock, buffer, 255);
    if (n < 0) 
         cout << "ERROR reading from socket\n";
    printf("%s\n", buffer);
    close(sock);
    return 0;
	
}
