#pragma once

namespace inline_util
{
    __forceinline void memcpy(void* dest, void* src, unsigned int size) 
    {
        for (auto i = 0u; i < size; ++i)
            *((unsigned char*)dest + i) = *((unsigned char*)src + i);
    }

    __forceinline char* strcpy(char* destination, char* source)
    {
        char* start = destination;

        while (*source != '\0')
        {
            *destination = *source;
            destination++;
            source++;
        }

        *destination = '\0'; // add '\0' at the end
        return start;
    }

    __forceinline char* strncpy(char* destination, char* source, size_t num)
    {
        auto ptr = destination;
        while (num-- && (*destination++ = *source++));
        return ptr;
    }
    

    __forceinline size_t strlen(char* str)
    {
        size_t len = 0;
        while (*str++)
            ++len;
        return len;
    }

    __forceinline int strcmp(const char* a, const char* b)
    {
        while (*a && *a == *b) { ++a; ++b; }
        return (int)(unsigned char)(*a) - (int)(unsigned char)(*b);
    }

    __forceinline void swap_endianess(char* dest, char* src) {
        for (size_t i = 0, l = inline_util::strlen(src); i < l; i += 2) {
            dest[i] = src[i + 1];
            dest[i + 1] = src[i];
        }
    }

    __forceinline bool isspace(char x)
    {
        return x == ' ' || x == '\t';
    }

    __forceinline void convert_to_string(unsigned short* diskdata,
        int firstIndex,
        int lastIndex,
        char* buf)
    {
        int index = 0;
        int position = 0;

        //  each integer has two characters stored in it backwards
        for (index = firstIndex; index <= lastIndex; index++)
        {
            //  get high byte for 1st character
            buf[position++] = (char)(diskdata[index] / 256);

            //  get low byte for 2nd character
            buf[position++] = (char)(diskdata[index] % 256);
        }

        //  end the string 
        buf[position] = '\0';

        //  cut off the trailing blanks
        for (index = position - 1; index > 0 && isspace(buf[index]); index--)
            buf[index] = '\0';

        //return buf;
    }

    __forceinline void convert_to_diskdata(unsigned short* diskdata,
        int firstIndex,
        int lastIndex,
        char* buf)
    {
        int index = 0;
        int position = 0;

        //  each integer has two characters stored in it backwards
        for (index = firstIndex; index <= lastIndex; index++)
        {
            //  get high byte for 1st character
            //buf[position++] = (char)(diskdata[index] / 256);
            
            //  get low byte for 2nd character
            //buf[position++] = (char)(diskdata[index] % 256);
            auto c1 = buf[position++];
            auto c2 = buf[position++];
            diskdata[index] = (c1 << 8) | c2;
        }

        //return buf;
    }

    __forceinline char tolower(char c)
    {
        if (('A' <= c) && (c <= 'Z'))
            c = 'a' + (c - 'A');
        return c;
    }

    __forceinline bool isprint(char c)
    {
        return (unsigned)c - 0x20 < 0x5f;
    }

    __forceinline bool is_good_char(char c)
    {
        const auto u = uint8_t(c);
        return (u >= uint8_t('0') && u <= uint8_t('9'))
            || (u >= uint8_t('A') && u <= uint8_t('Z'))
            || (u >= uint8_t('a') && u <= uint8_t('z'));
    }

    __forceinline bool is_hex(char c)
    {
        const auto u = uint8_t(c);
        return (u >= uint8_t('0') && u <= uint8_t('9'))
            || (u >= uint8_t('A') && u <= uint8_t('F'))
            || (u >= uint8_t('a') && u <= uint8_t('f'));
    }

    __forceinline char unhex_char(char c)
    {
        const auto u = uint8_t(c);
        if (u >= uint8_t('0') && u <= uint8_t('9'))
            return u - uint8_t('0');
        if (u >= uint8_t('A') && u <= uint8_t('F'))
            return u - uint8_t('A') + 0xA;
        if (u >= uint8_t('a') && u <= uint8_t('f'))
            return u - uint8_t('a') + 0xa;
        return 0xFF;
    }

    __forceinline char hex_char(char v)
    {
        if (v < 0xA)
            return char(uint8_t('0') + v);
        return char(uint8_t('A') + v - 0xA);
    }

    __forceinline void hex_byte(char v, char& c1, char& c2) 
    { 
        volatile auto v1 = v;
        v1 = v1 >> 4;

        volatile auto v2 = v;
        v2 = v2 & 0xF;

        c1 = hex_char(v1);
        c2 = hex_char(v2);
    }

    __forceinline char unhex_byte(char a, char b) 
    { 
        volatile auto hex1 = unhex_char(a);
        volatile auto hex2 = unhex_char(b);
        volatile auto result = (hex1 << 4);
        result += hex2;
        return result;
    }
    
    __forceinline void
        scsi_format_id_string(char* out, const uint8_t* in, int n)
    {
        char tmp[65];
        n = n > 64 ? 64 : n;
        inline_util::strncpy(tmp, (char*)in, n);
        tmp[n] = '\0';

        // Find the first non-space character (maybe none).
        int first = -1;
        int i;
        for (i = 0; tmp[i]; i++)
            if (!isspace((int)tmp[i])) {
                first = i;
                break;
            }

        if (first == -1) {
            // There are only space characters.
            out[0] = '\0';
            return;
        }

        // Find the last non-space character.
        for (i = strlen(tmp) - 1; i >= first && isspace((int)tmp[i]); i--);
        int last = i;

        inline_util::strncpy(out, tmp + first, last - first + 1);
        out[last - first + 1] = '\0';
    }

}