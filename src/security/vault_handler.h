#ifndef vault_handler_H
#define vault_handler_H

#include <fstream>
#include <string>
#include <unordered_map>   
#include <sodium.h>

class vault_handler
{
public:
    vault_handler(string filename);
    ~vault_handler();

    void CreateVault();
    std::string ReadVault();
    void UpdateVault(const std::string& newData);
    void DeleteVault();

    unsigned char* vaultKey;

private:
    std::string DeriveKey();
    void Encrypt(std::string password, std::string pepperAddress);
    void Decrypt(std::string password, std::string pepperAddress);

    std::string key;

    std::unordered_map<std::string, std::string> vaultData;
};

#endif // vault_handler_H
