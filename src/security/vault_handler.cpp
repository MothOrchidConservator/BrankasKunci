#include "vault_handler.h"
#include <vector>
#include <fstream>
#include <iostream>
#include <string>
#include <cstdio>

using namespace std;

vault_handler::vault_handler(string filename)
{
    if (sodium_init() < 0)
    {
        throw std::runtime_error("libsodium init failed");
    }

    string vaultName = filename;
    string vaultAddress = "data/vaults/";
    sodium_memzero(vaultKey, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
    sodium_free(vaultKey);

    for (auto& entry : vaultData) {
        sodium_memzero(&entry.second[0], entry.second.size());
    }
    vaultData.clear();
}

vault_handler::~vault_handler()
{
}

void vault_handler::CreateVault()
{
    ofstream out("data/vaults/user_vault.dat", std::ios::binary);//use formatstring &s&s, faultaddress, vaultname
    if (!out) {
        throw std::runtime_error("Failed to create vault file");
    }

    std::string header = "VAULTv1";
    out.write(header.c_str(), header.size());

    out.close();
    std::cout << "Vault file created.\n";
}

string vault_handler::ReadVault()
{
    std::ifstream in("data/vaults/user_vault.dat", std::ios::binary);
    if (!in) {
        throw std::runtime_error("Vault file not found");
    }

    std::string contents((std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>());
    in.close();

    std::cout << "Vault file read.\n";
    return contents;
}

void vault_handler::UpdateVault(const std::string& newData)
{
    std::ofstream out("data/vaults/user_vault.dat", std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("Failed to open vault file for update");
    }

    out.write(newData.c_str(), newData.size());
    out.close();

    std::cout << "Vault file updated.\n";
}

void vault_handler::DeleteVault()
{
    std::string path = "data/vaults/user_vault.dat";
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) {
        std::cerr << "Vault file not found.\n";
        return;
    }

    std::streamsize size = in.tellg();
    in.close();

    std::ofstream out(path, std::ios::binary | std::ios::in);
    std::vector<char> buffer(size);
    randombytes_buf(buffer.data(), buffer.size());
    out.write(buffer.data(), buffer.size());
    out.close();

    if (std::remove(path.c_str()) == 0) {
        std::cout << "Vault securely deleted.\n";
    }
    else {
        std::cerr << "Failed to delete vault.\n";
    }
}


void vault_handler::Encrypt(string password, string pepperAddress)
{
}

void vault_handler::Decrypt(string password, string pepperAddress)
{
}

string vault_handler::DeriveKey()
{
	return "key";
}