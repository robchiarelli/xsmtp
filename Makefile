CC = g++
CFLAGS = -g -O2
CFLAGS_EXTRA = -lpthread -lssl -lcrypto
BIN_FILE = client
OBJ_FILES = module_mail.o module_user.o hash.o register.o xsmtp.o xpop3.o client.o
SRC_FILES = module_mail.cpp module_user.cpp hash.cpp register.cpp xsmtp.cpp xpop3.cpp client.cpp

all: $(BIN_FILE)
$(BIN_FILE): $(OBJ_FILES) client.cpp
	$(CC) $(CFLAGS) $(OBJ_FILES) -o $(BIN_FILE) $(CFLAGS_EXTRA)

$(OBJ_FILES):
	$(CC) $(CFLAGS) -c $(SRC_FILES)

#register: register.cpp
#	$(CC) $(CFLAGS) -c hash.cpp
#	$(CC) -g hash.o -o register register.cpp -lssl -lcrypto

clean:
	rm $(OBJ_FILES) $(BIN_FILE)
