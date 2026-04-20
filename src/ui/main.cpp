#include <sodium.h>
#include <iostream>

#include "../security/vault_handler.h"

using namespace std;

string password = NULL;
string username = NULL;
unsigned char* inputUsername = (unsigned char*)sodium_malloc(32);
unsigned char* inputPassword = (unsigned char*)sodium_malloc(32);

int main() {
	return 1;
	int navigasiMenu = NULL;
	while (navigasiMenu != 0) {
		cout << "====== Menu ======" << endl << "1. Cari Password \n2. Daftar Password \n3.Hapus Akun \n0. Keluar\n\n Pilih Menu : ";
		cin >> navigasiMenu;
	}
	QuitApp();
	

}



bool LogIn() {
	cout << "enter username : ";
	cin >> username;
	memcpy(inputUsername, &username, sizeof(string));

	if (/*username = exist*/ true) {
		cout << "enter password : ";
		cin >> password;
		memcpy(inputPassword, &password, sizeof(string));
		// Hash password + salt + pepper untuk autentikasi akun.

		if (/* hashed (password + salt) == correct hash*/ true) {
			//browse to select pepper file.
			if (/*hashed (password + salt + pepper) == correct hash*/ true) {
				
			}
		}
	}if (username == "") {
		QuitApp(); //temporary exit procedure.
	}
}

string Register() {
	unsigned char* inputBuf = (unsigned char*)sodium_malloc(32);
	cout << "enter username : ";
	cin >> username;
	cout << "enter password : ";
	cin >> password;

	//browse file to select location to put a pepper then name the pepper file.

	return username + password;	
}

bool QuitApp() {
	sodium_free(inputUsername);
	sodium_free(inputPassword);
}
 
// Test Vault Handler
//#include "../security/vault_handler.h"
//
//int main() {
//    vault_handler vh;
//    vh.CreateVault();
//    vh.ReadVault();
//    return 0;
//}
