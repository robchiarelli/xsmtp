#include <iostream>

#include "xsmtp.h"
#include "register.h"
//#include "xpop3.h"
#include "login.h"
#include "mail_client.h"
using namespace std;

void logged_in(int &choice) {
	cout << "To register a user, press 1\n"
		 << "To send mail, press 2\n"
		 << "To check mail, press 3\n"
		 << "To exit the client, press 4\n";
	cin >> choice;
}

void logged_out(int &choice) {
	cout << "To register a user, press 1\n"
		 << "To log in, press 2\n"
		 << "To exit the client, press 4\n";
	cin >> choice;
}

int main() {
	int choice;
	string user;
	bool login_flag = false;
	while(true) {
		if (login_flag) {
			logged_in(choice);
			if (choice == 1) user = register_main();
			else if (choice == 2) mail_client("localhost", 25, user);
			else if (choice == 3) mail_client("localhost", 110, user);
			else break;
		}
		else {
			logged_out(choice);
			if (choice == 1) user = register_main();
			else if (choice == 2) login_flag = validate_user();
			else break;
		}
	}
	return 0;
}
