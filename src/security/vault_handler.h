#ifndef vault_handler_H
#define vault_handler_H

#include <fstream>
#include <string>  
#include <sodium.h>
#include "../utils/secure_allocator.h"

class vault_handler
{
public:
    vault_handler(std::string username, std::string vaultAddress, SecureString vaultPassword, SecureString vaultPepper);
    ~vault_handler();

    void CreateVault();
    SecureString ReadVault();
    void UpdateVault(const SecureString& newData);
    void DeleteVault();


private:
    void DeriveKey(SecureString vaultPassword, SecureString vaultPepper);
    void Encrypt();
    void Decrypt();
    std::string vaultName;
    std::string vaultAddress;
    SecureBuffer vaultKey;
    SecureString vaultData;
    SecureString vaultPassword;
    SecureString vaultPepper;
    
};

#endif // vault_handler_H
