#include <iostream>

#include "xsmtp.h"
#include "register.h"
#include "xpop3.h"
#include "login.h"
using namespace std;

void logged_in(int &choice) {
	cout << "To register a user, press 1\n"
		 << "To send mail, press 2\n"
		 << "To check mail, press 3\n"
		 << "To modify your account information, press 4\n"
		 << "To exit the client, press 5\n";
	cin >> choice;
}

void logged_out(int &choice) {
	cout << "To register a user, press 1\n"
		 << "To log in, press 2\n"
		 << "To exit the client, press 5\n";
	cin >> choice;
}

int main() {
	int choice;
	bool login_flag = false;
	while(true) {
		if (login_flag) {
			logged_in(choice);
			if (choice == 1) register_main();
			else if (choice == 2) xsmtp_main();
			else if (choice == 3) xpop3_main();
			else if (choice == 4) cout << "not implemented\n";
			else if (choice == 5) break;
		}
		else {
			logged_out(choice);
			if (choice == 1) register_main();
			else if (choice == 2) login_flag = validate_user();
			else if (choice == 5) break;
		}
	}
	return 0;
}
