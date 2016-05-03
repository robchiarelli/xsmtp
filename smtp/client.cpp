#include <iostream>

#include "xsmtp.h"
#include "register.h"
//#include "xpop3.h"
#include "login.h"
#include "mail_client.h"
using namespace std;

string user = "rob@localhost.com";

//void logged_in(int &choice) {
int logged_in() {
	int choice = 0;
	cout << "To register a user, press 1\n"
		 << "To send mail, press 2\n"
		 << "To check mail, press 3\n"
		 << "To exit the client, press 4\n";
	cin >> choice;
	return choice;
}

//void logged_out(int &choice) {
int logged_out() {
	int choice = 0;
	cout << "To register a user, press 1\n"
		 << "To log in, press 2\n"
		 << "To exit the client, press 4\n";
	cin >> choice;
	return choice;
}

int main() {
	bool login_flag = false;
	while(true) {
		//int choice = 0
		if (login_flag) {
			int choice = logged_in();
			if (choice == 1) register_main();
			else if (choice == 2) mail_client("localhost", 25, user);
			else if (choice == 3) mail_client("localhost", 110, user);
			else break;
		}
		else {
			int choice = logged_out();
			if (choice == 1) register_main();
			else if (choice == 2) login_flag = validate_user();
			else break;
		}
	}
	return 0;
}
