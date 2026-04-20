#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include <iostream>
#include <string>
#include <sodium.h>

using namespace std;

class authenticator
{
public:
	authenticator();
	~authenticator();
	int SodiumInitialize();
	void Hash();
	void GeneratePepper();

private:
	void ReadPepper();
	void ReadSalt();
};
#endif // !1
