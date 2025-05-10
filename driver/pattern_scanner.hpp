#pragma once
#include <ntdef.h>

typedef DWORD_PTR uintptr_t;
typedef UINT8 uint8_t;



class PatternScanner
{
public:
	void set_region(uintptr_t start, size_t size);

	uintptr_t find_call(const char* pattern);
	uintptr_t find_call_code(const uint8_t* binary, size_t len);

	uintptr_t find_offset(const char* pattern, size_t pos);
	uintptr_t find_offset_code(const uint8_t* binary, size_t len, size_t pos);

	uintptr_t find_memory(const char* pattern);
	uintptr_t find_memory_code(const uint8_t* binary, size_t len);

private:

	uint8_t hex_to_bin(const char* str);
	void str_to_bin(const char* str_pattern, uint8_t* bin, size_t* outlen);


	uintptr_t	m_start;
	size_t		m_size;
};

extern PatternScanner scanner;


#define PATTERN_SET(start, len)(scanner.set_region((uintptr_t)start, (size_t)len))

#define PATTERN_FIND_CALL_CODE(binary) (scanner.find_call_code((uint8_t*)binary, ARRAYSIZE(binary)))
//#define PATTERN_FIND_CALL(str) (scanner.find_call((const char*)str))

#define PATTERN_FIND_CODE(binary) (scanner.find_memory_code((uint8_t*)binary, ARRAYSIZE(binary)))
//#define PATTERN_FIND(binary) (scanner.find_memory((const char*)binary));

#define PATTERN_FIND_OFS_CODE(binary, pos) (scanner.find_offset_code((uint8_t*)binary, ARRAYSIZE(binary), pos))
//#define PATTERN_FIND_OFS(binary, pos) (scanner.find_offset((const char*)binary, pos));
