#include "vault_handler.h"
#include <vector>
#include <fstream>
#include <iostream>
#include <string>
#include <cstdio>
#include "../utils/secure_allocator.h"
#include <stdexcept>
#include <format>
#include <filesystem> 

static uint32_t toNetwork(uint32_t value) {
    unsigned char* p = reinterpret_cast<unsigned char*>(&value);
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) | (static_cast<uint32_t>(p[3]));
}

static uint32_t fromNetwork(uint32_t value) {
    return toNetwork(value);
}

using namespace std;
vault_handler::vault_handler(const std::string& username, const std::string& vaultAddress, const SecureString& vaultPassword, const SecureString& vaultPepper) {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium initialization failed. The application cannot continue safely.");
    }

    if (username.empty() || username.length() > 64)
        throw std::invalid_argument("Vault name must be 1-64 characters.");
    for (char c : username) {
        if (!isalnum(c) && c != '-')
            throw std::invalid_argument("Vault name must be alphanumeric and hyphens only.");
    }
    this->vaultName = username;
    this->vaultAddress = vaultAddress;
    this->vaultPassword = vaultPassword;
    this->vaultPepper = vaultPepper;
    this->vaultPath = vaultAddress + vaultName + "_vault.dat";
    vaultKey = static_cast<unsigned char*>(sodium_malloc(KEY_SIZE));
    sodium_memzero(vaultKey, KEY_SIZE);
}

vault_handler::~vault_handler() {
    sodium_memzero(vaultKey, KEY_SIZE);
    sodium_free(vaultKey);
}

void vault_handler::CreateVault() {
    std::ofstream vault(vaultPath, std::ios::binary);
    if (!vault.is_open()) {
        throw std::runtime_error("failed to create vault.");
    }
    const char header[] = { 'V','A','U','L','T','\0','v','1','\0' };
    vault.write(header, 9);
    vault.close();
}

SecureString vault_handler::ReadVault() {
    std::ifstream vault(vaultPath, std::ios::binary);
    if (!vault.is_open()) {
        throw std::runtime_error("failed to open vault.");
    }
    vault.seekg(0, std::ios::end);
    size_t size = vault.tellg();
    vault.seekg(0, std::ios::beg);
    vault.seekg(9);

    SecureString vaultData(size - 9);
    vault.read(reinterpret_cast<char*>(vaultData.data()), size - 9);
    return vaultData;
}

void vault_handler::UpdateVault(const SecureString& newData) {
    std::ofstream vault(vaultPath, std::ios::binary);
    vault.write(reinterpret_cast<const char*>(newData.data()), newData.size());
    vault.close();
}

void vault_handler::DeleteVault() {
    if (!std::filesystem::exists(vaultPath)) {
        return;
    }

    size_t fileSize = std::filesystem::file_size(vaultPath);
    const size_t bufferSize = 4096;

    {
        std::vector<char> buffer(bufferSize, 0x00);
        std::ofstream vault(vaultPath, std::ios::binary);
        vault.seekp(0);
        size_t remaining = fileSize;
        while (remaining > 0) {
            size_t toWrite = (remaining < bufferSize) ? remaining : bufferSize;
            vault.write(buffer.data(), toWrite);
            remaining -= toWrite;
        }
        vault.close();
    }

    {
        std::vector<char> buffer(bufferSize, 0xFF);
        std::ofstream vault(vaultPath, std::ios::binary);
        vault.seekp(0);
        size_t remaining = fileSize;
        while (remaining > 0) {
            size_t toWrite = (remaining < bufferSize) ? remaining : bufferSize;
            vault.write(buffer.data(), toWrite);
            remaining -= toWrite;
        }
        vault.close();
    }

    {
        std::vector<char> buffer(bufferSize);
        std::ofstream vault(vaultPath, std::ios::binary);
        vault.seekp(0);
        size_t remaining = fileSize;
        while (remaining > 0) {
            size_t toWrite = (remaining < bufferSize) ? remaining : bufferSize;
            randombytes_buf(buffer.data(), toWrite);
            vault.write(buffer.data(), toWrite);
            remaining -= toWrite;
        }
        vault.close();
    }

    if (std::remove(vaultPath.c_str()) != 0) {
        throw std::runtime_error("Error deleting vault.");
    }
}

void vault_handler::WriteLengthPrefixed(SecureBuffer& output, const char* data, uint32_t length) {
    uint32_t netLength = toNetwork(length);
    const unsigned char* lenBytes = reinterpret_cast<const unsigned char*>(&netLength);
    output.insert(output.end(), lenBytes, lenBytes + sizeof(netLength));
    output.insert(output.end(), data, data + length);
}

bool vault_handler::ReadLengthPrefixed(const unsigned char*& pos, const unsigned char* end, SecureBuffer& output)
{
    if (end - pos < static_cast<ptrdiff_t>(sizeof(uint32_t))) {
        return false;
    }
    uint32_t netLength;
    memcpy(&netLength, pos, sizeof(netLength));
    pos += sizeof(netLength);

    uint32_t length = fromNetwork(netLength);
    if (end - pos < static_cast<ptrdiff_t>(length)) {
        return false;
    }
    output.insert(output.end(), pos, pos + length);
    pos += length;
    return true;
}

void vault_handler::DeriveKey(const SecureString& password, const SecureBuffer& salt, const SecureString& pepper)
{
    SecureString combined = password;
    combined.insert(combined.end(), pepper.begin(), pepper.end());

    if (crypto_pwhash(
        this->vaultKey,
        KEY_SIZE,
        combined.data(),
        combined.size(),
        reinterpret_cast<const unsigned char*>(salt.data()),
        crypto_pwhash_OPSLIMIT_SENSITIVE,
        crypto_pwhash_MEMLIMIT_SENSITIVE,
        crypto_pwhash_ALG_ARGON2ID13
    ) != 0) {
        throw std::runtime_error("Key derivation failed (Out of memory)");
    }
}

void vault_handler::Encrypt() {
    SecureBuffer salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());
    SecureBuffer nonce(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    DeriveKey(vaultPassword, salt, vaultPepper);
    SecureBuffer plaintext;
    for (const auto& entry : entries) {
        WriteLengthPrefixed(plaintext, entry.site.data(), static_cast<uint32_t>(entry.site.size()));
        WriteLengthPrefixed(plaintext, entry.username.data(), static_cast<uint32_t>(entry.username.size()));
        WriteLengthPrefixed(plaintext, entry.password.data(), static_cast<uint32_t>(entry.password.size()));
    }

    SecureBuffer ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len = 0;
    const char header[] = { 'V','A','U','L','T','\0','v','1','\0' };
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(),
        &ciphertext_len,
        plaintext.data(),
        plaintext.size(),
        reinterpret_cast<const unsigned char*>(static_cast<const void*>(header)),
        9,
        NULL,
        nonce.data(),
        vaultKey
    ) != 0) {
        throw std::runtime_error("Encryption failed.");
    }

    std::ofstream file(vaultPath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open vault file for writing.");
    }
    file.write(header, 9);
    file.write(reinterpret_cast<const char*>(salt.data()), salt.size());
    file.write(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext_len);
    file.close();

    sodium_memzero(plaintext.data(), plaintext.size());
}

void vault_handler::Decrypt() {
    std::ifstream file(vaultPath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open vault file.");
    }

    char readHeader[9];
    file.read(readHeader, 9);
    const char expectedHeader[] = { 'V','A','U','L','T','\0','v','1','\0' };
    if (memcmp(readHeader, expectedHeader, 9) != 0) {
        throw std::runtime_error("Invalid vault file or wrong version.");
    }

    SecureBuffer salt(crypto_pwhash_SALTBYTES);
    file.read(reinterpret_cast<char*>(salt.data()), salt.size());

    SecureBuffer nonce(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    file.read(reinterpret_cast<char*>(nonce.data()), nonce.size());

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    size_t ciphertextSize = fileSize - 9 - crypto_pwhash_SALTBYTES -
        crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    file.seekg(9 + crypto_pwhash_SALTBYTES + crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

    SecureBuffer ciphertext(ciphertextSize);
    file.read(reinterpret_cast<char*>(ciphertext.data()), ciphertextSize);

    DeriveKey(vaultPassword, salt, vaultPepper);

    SecureBuffer plaintext(ciphertextSize);
    unsigned long long plaintext_len = 0;
    const char header[] = { 'V','A','U','L','T','\0','v','1','\0' };

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext.data(),
        &plaintext_len,
        NULL,
        ciphertext.data(),
        ciphertextSize,
        reinterpret_cast<const unsigned char*>(static_cast<const void*>(header)),
        9,
        nonce.data(),
        vaultKey
    ) != 0) {
        throw std::runtime_error("Decryption failed. Wrong password, tampered file, or wrong pepper.");
    }

    entries.clear();
    const unsigned char* pos = plaintext.data();
    const unsigned char* end = plaintext.data() + plaintext_len;

    while (pos < end) {
        VaultEntry entry;

        SecureBuffer field;
        if (!ReadLengthPrefixed(pos, end, field)) break;
        entry.site.assign(field.begin(), field.end());

        field.clear();
        if (!ReadLengthPrefixed(pos, end, field)) break;
        entry.username.assign(field.begin(), field.end());

        field.clear();
        if (!ReadLengthPrefixed(pos, end, field)) break;
        entry.password.assign(field.begin(), field.end());

        entries.push_back(entry);
    }

    sodium_memzero(plaintext.data(), plaintext.size());
}