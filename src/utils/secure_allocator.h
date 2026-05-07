#ifndef SECURE_ALLOCATOR_H
#define SECURE_ALLOCATOR_H

#include <sodium.h>
#include <cstddef>
#include <vector>

template <class T>
struct SodiumAllocator
{
	using value_type = T;

	SodiumAllocator() noexcept = default;
	template <class U> constexpr SodiumAllocator(const SodiumAllocator<U>&) noexcept {}

	T* allocate(std::size_t n) {
		return static_cast<T*>(sodium_malloc(n * sizeof(T)));
	}

	void deallocate(T* p, std::size_t n) noexcept {
		sodium_memzero(p, n * sizeof(T));
		sodium_free(p);
	}
};

using SecureBuffer = std::vector<unsigned char, SodiumAllocator<unsigned char>>;
using SecureString = std::vector<char, SodiumAllocator<char>>;

#endif // !SECURE_ALLOCATOR_H


