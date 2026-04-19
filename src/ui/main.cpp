#include <sodium.h>
#include <iostream>

int main() {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed!" << std::endl;
        return 1;
    }
    std::cout << "libsodium is working!" << std::endl;
    return 0;
}
