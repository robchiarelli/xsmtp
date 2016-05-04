# xsmtp + xpop3 = xmail (now with crypto)

A simple SMTP mail server, a tiny but complete realization of smtp protocol.
A simple POP3 mail server, a tiny but complete realization of pop3 protocol.
A client that will interact with these servers...


## Usage
```
python hybrid.py register "username,salt,hash"
python hybrid.py keygen
python hybrid.py encrypt username message
python hybrid.py decrypt username
```

`hybrid.py` is used by the client application to encrypt and decrypt. It writes files `enc` for encyrption, `dec` for decryption, `reg` for registering. The client can read these files to display to user or send to server.

```
./client
```
Instructions in binary for how how to run.

```
./xsmtp
```
Explained below.

```
python register.py
```
(Currently not working)
user registration server. Client sends registration information to it, encrypted with server's public key which is known to all parties. 

```
./xpop3
```
Not working regularly. Not yet supported by client.


## Features

- OS: only for Linux/Unix plantform  
- Multithread: create a thread for each client's request  
- Authentication: store username and passwd to a file
- Base64 encode and decode  

## Crypto
- SHA256 salted hashes of passwords
- RSA
- HMAC

## Usage  
1) Get the source    
```
git clone https://github.com/ibillxia/xsmtp.git
cd xsmtp
```

2) Edit Config
Set the user data storage directory:
```
vim conf.h
```
Set the variable `data_dir` to `/home/YourName/data`. 

## XSMTP

3) Add files and user account
```
cd /home/YourName/
mkdir data
vim userinfo
#add two users in this file
#bill@localhost.com
#alice@localhost.com
#then write and quit
touch userstat
```

4) Send Mail Example
Run the executable file in one terminal:  
```
sudo xsmtp
```
This started the mail server. And now you can send e-mail to the server in another terminal like this: 
```
telnet localhost 25
S: 220 Ready
C: HELO
S: 250 OK
C: MAIL FROM:<bill@localhost.com>
S: 250 OK
C: RCPT TO:<alice@localhost.com>
S: 250 OK
C: DATA
S: 354 Send from Rising mail proxy
C: Hello Alice. This is a test message.<CR><LF>.<CR><LF>
S: 250 OK
C: QUIT
S: 221 Bye
```
Well done!

## XPOP3
3) Recieve e-mail from a mail server
Run the executable file in one terminal:  

```
sudo ./pop3
```

This started the mail server. And now you can recieve e-mail from the server in **another terminal** like this: 

```
telnet localhost 110
S: +OK Welcome
C: USER alice@localhost.com
S: +OK
C: PASS 123456
S: +OK
C: STAT
S: +OK
C: LIST
S: +OK
C: QUIT
S: +OK
```

Well done!


## About SMTP protocal  

This program is a simple mail dispatcher via smtp protocol. It runs only on Linux/Unix plantforms.
For more about SMTP, please refer to wiki and it's RFC documents:   
[wiki: Simple_Mail_Transfer_Protocol](http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol)  
[RFC 5321 – The Simple Mail Transfer Protocol](http://tools.ietf.org/html/rfc5321)  

## About POP3 protocal  

This program is a simple mail receiver via pop3 protocol. It runs only on Linux/Unix plantforms.
For more about pop3 and it's RFC documents, please refer to wiki and RFC doc: 
[Post_Office_Protocol](http://en.wikipedia.org/wiki/Post_Office_Protocol)  
[Post Office Protocol - Version 3(STD 53)](http://tools.ietf.org/html/rfc1939)  

## Lisense

The MIT License (MIT)
Copyright (C) 2011-2014 Bill Xia (ibillxia@gmail.com) 
All rights reserved.
