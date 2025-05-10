#pragma once

//#include "crtdef.hpp"
#include <stdint.h>

typedef uint64_t hash64_t;
typedef uint32_t hash32_t;


constexpr uint32_t val_32_const = 0x811c9dc5;
constexpr uint32_t prime_32_const = 0x1000193;
constexpr uint64_t val_64_const = 0xcbf29ce484222325;
constexpr uint64_t prime_64_const = 0x100000001b3;

constexpr char constexpr_ch_to_lower(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c + 32;

	return c;
}


__forceinline const hash32_t hash32(const void* key) {

	const char* data = (char*)key;
	uint32_t hash = 0x811c9dc5;
	uint32_t prime = 0x1000193;

	while (*data)
	{
		uint8_t value = *data;
		hash = hash ^ value;
		hash *= prime;
		data++;
	}

	return hash;

} //hash_32_fnv1a

static hash64_t hash64(const void* key) {

	const char* data = (char*)key;
	uint64_t hash = 0xcbf29ce484222325;
	uint64_t prime = 0x100000001b3;

	while(*data)
	{
		uint8_t value = *data;
		hash = hash ^ value;
		hash *= prime;

		data++;
	}

	return hash;

} //hash_64_fnv1a


__forceinline const hash64_t fnva1_buffer(const void* key, size_t len) {

	const char* data = (char*)key;
	uint64_t hash = 0xcbf29ce484222325;
	uint64_t prime = 0x100000001b3;

	size_t offset = 0;

	while (offset < len)
	{
		uint8_t value = *data;
		hash = hash ^ value;
		hash *= prime;

		data++;
		offset++;
	}

	return hash;

} //hash_64_fnv1a


__forceinline constexpr hash64_t kHash64(const char* const str, const uint64_t value = val_64_const) noexcept {
	return (str[0] == '\0') ? value : kHash64(&str[1], (value ^ uint64_t(str[0])) * prime_64_const);
}
__forceinline constexpr hash64_t kHash64l(const char* const str, const uint64_t value = val_64_const) noexcept {
	return (str[0] == '\0') ? value : kHash64l(&str[1], (value ^ uint64_t(constexpr_ch_to_lower(str[0]))) * prime_64_const);
}


__forceinline constexpr hash32_t kHash32(const char* const str, const uint32_t value = val_32_const) noexcept {
	return (str[0] == '\0') ? value : kHash32(&str[1], (value ^ uint32_t(str[0])) * prime_32_const);
}

unsigned int calcHash(const char* s);
unsigned int riWHash(const wchar_t* s);