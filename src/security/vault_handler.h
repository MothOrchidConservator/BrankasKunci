#ifndef vault_handler_H
#define vault_handler_H

#include <fstream>
#include <string>  
#include <sodium.h>
#include "../utils/secure_allocator.h"
#include <cstdint>

class vault_handler
{
public:
    vault_handler(const std::string& username, const std::string& vaultAddress, const SecureString& vaultPassword, const SecureString& vaultPepper);
    ~vault_handler();
    void CreateVault();
    SecureString ReadVault();
    void UpdateVault(const SecureString& newData);
    void DeleteVault();


private:
    static void WriteLengthPrefixed(SecureBuffer& output, const char* data, uint32_t length);
    static bool ReadLengthPrefixed(const unsigned char*& pos, const unsigned char* end, SecureBuffer& output);
    void DeriveKey(const SecureString& password, const SecureBuffer& salt, const SecureString& pepper);
    void Encrypt();
    void Decrypt();
    std::string vaultName;
    std::string vaultAddress;
    std::string vaultPath;
    SecureString vaultPassword;
    SecureString vaultPepper;
    unsigned char* vaultKey;
    static constexpr size_t KEY_SIZE = 32;
    struct VaultEntry {SecureString site; SecureString username; SecureString password;};
    std::vector<VaultEntry> entries;
};


#endif // vault_handler_H
