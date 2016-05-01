#include <iostream>

#include "xsmtp.h"
#include "register.h"
#include "xpop3.h"
using namespace std;

void client(int &choice) {
	cout << "To register a user, press 1\n"
		 << "To send mail, press 2\n"
		 << "To check mail, press 3\n"
		 << "To modify your account information, press 4\n"
		 << "To exit the client, press 5\n";
	cin >> choice;
}

int main() {
	int choice;
	while(true) {
		client(choice);
		if (choice == 1) register_main();
		else if (choice == 2) xsmtp_main();
		else if (choice == 3) xpop3_main();
		else if (choice == 4) cout << "not implemented\n";
		else if (choice == 5) break;
		/*switch(choice) {
			case 1: register_main();
			case 2: xsmtp_main();
			case 3: xpop3_main;
			case 4: cout << "not implemented yet" << endl;
			case 5: break;
		}*/
	}
	return 0;
}
