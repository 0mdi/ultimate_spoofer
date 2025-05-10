// shellcode_builder.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <cstdint>
#include <Windows.h>
#include <string>
#include <unordered_map>
#include <filesystem>
#include <time.h>

struct shellcode_function_t {
	std::string name;
	bool extracted = false;
};

#define SHELLCODE_END_MARKER_MAGIC 0xB16B00B5B16B00B5
#define CONTEXT_DEFAULT_MAGIC_VALUE 0xDEAD1234DEADBEEF


std::unordered_map<std::string, shellcode_function_t> function_section_map
{
	{"shell1", {"SrbShimHookDeviceControlHook1"}},
	{"shell2", {"SrbShimHookDeviceControlHook2"}},
	{"shell3", {"storage_query_ioc"}},
	{"shell4", {"ata_pass_ioc"}},
	{"shell5", {"smart_data_ioc"}},
	{"shell6", {"DeviceIdShimHookDeviceControlHook1"}},
	{"shell7", {"DeviceIdShimHookDeviceControlHook2"}},
	{"shell8", {"ATADeviceIdShimHookDeviceControlHook1"}},
	{"shell9", {"ATADeviceIdShimHookDeviceControlHook2"}},
	{"shell10", {"part_info_ioc"}},
	{"shell11", {"part_layout_ioc"}},
	{"shell12", {"scsi_miniport_ioc"}},
	{"shell13", {"scsi_pass_through_direct_ioc"}},
	{"shell14", {"nic_ioc"}},
	{"shell15", {"NicControlHook"}},
	{"shell16", {"nsi_ioc"}},
	{"shell17", {"NsiEnumerateObjectsAllParametersExHook"}},
	{"shell18", {"NsiControlHook"}}
};

void build_helper_functions(std::string name, std::ofstream& os)
{
	auto write_string_newline = [&](std::string str) -> void {
		str += "\n";
		os.write(str.data(), str.length());
	};

	auto arrayName = "sh" + name;
	auto keyName = "shKey" + name;
	
	auto write_vars = [&]() {
		write_string_newline("	unsigned char* psh = (unsigned char*)(&" + arrayName + "[0]);");
		write_string_newline("	auto key = " + keyName + ";");
		write_string_newline("	auto size = sizeof(" + arrayName  + ");");
	};



	write_string_newline("__forceinline unsigned char* SHGetDecrypted" + name + "()");
	write_string_newline("{");
	write_vars();
	write_string_newline("	for (int i = 0; i <= size - 4; i += 0x4) {");
	write_string_newline("		auto ptr = (int*)(&psh[i]);");
	write_string_newline("		*ptr ^= (key + i);");
	write_string_newline("	}");
	write_string_newline("	return psh;");
	write_string_newline("}");

	write_string_newline("__forceinline void SHDestroy" + name + "()");
	write_string_newline("{");
	write_vars();
	write_string_newline("	for (int i = 0; i <= size - 4; i += 0x4) {");
	write_string_newline("		auto ptr = (int*)(&psh[i]);");
	write_string_newline("		*ptr = 0x00;");
	write_string_newline("	}");
	write_string_newline("}");


	write_string_newline("__forceinline unsigned long long SHGetSize" + name + "()");
	write_string_newline("{");
	write_string_newline("	return sizeof(" + arrayName + ");");
	write_string_newline("}");

}

int main(int argc, const char** argv)
{
	srand(time(0));

	if (argc < 2) {
		std::cout << "[-] input path is missing" << std::endl;
		return 1;
	}

	if (argc < 3) {
		std::cout << "[-] output path is missing" << std::endl;
		return 1;
	}

	std::string output_path(argv[2]);

	std::error_code ec;
	if (!std::filesystem::exists(argv[2], ec)) {
		std::filesystem::create_directory(argv[2], ec);
		if (ec) {
			std::cout << "[-] failed to create output directory" << std::endl;
		}
	}


	std::ifstream in(argv[1], std::ios::binary);
	if (!in.is_open())
	{
		std::cout << "[-] failed to open input file" << std::endl;
		return 2;
	}

	in.seekg(0, std::ios::end);
	auto filesize = (size_t)in.tellg();
	in.seekg(0, std::ios::beg);

	auto file_buffer = new uint8_t[filesize];
	in.read((char*)file_buffer, filesize);

	auto dos_header = (IMAGE_DOS_HEADER*)(file_buffer);
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cout << "[-] invalid input file" << std::endl;
		return 3;
	}

	auto nt_header = (IMAGE_NT_HEADERS64*)(file_buffer + dos_header->e_lfanew);
	if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
		std::cout << "[-] invalid input file" << std::endl;
		return 3;
	}

	std::cout << "[+] extracting shellcode..." << std::endl;

	auto current_section = IMAGE_FIRST_SECTION(nt_header);
	for (unsigned int current_section_index = 0; current_section_index < nt_header->FileHeader.NumberOfSections; 
		current_section_index++, current_section++) {
		//std::cout << "[+] processing section " << current_section->Name << std::endl;

		auto iter = function_section_map.find(std::string((const char*)current_section->Name));
		if (iter == function_section_map.end()) {
			//std::cout << "[*] skipping undefined section " << current_section->Name << std::endl;
			continue;;
		}

		std::cout << "[+] extracting shellcode of " << iter->second.name << std::endl;

		auto raw_data_ptr = (uint8_t*)(current_section->PointerToRawData + file_buffer);
		auto raw_data_size = current_section->SizeOfRawData;



		size_t end_marker_index = 0;

		//search for the end marker magic
		for (size_t cursor = 0; cursor < raw_data_size - sizeof(uintptr_t); cursor += 0x8) {
			if (*(uintptr_t*)(raw_data_ptr + cursor) == SHELLCODE_END_MARKER_MAGIC) {
				end_marker_index = cursor;
				break;
			}
		}

		if (end_marker_index == 0)
		{
			std::cout << "[-] failed to locate the end marker for section " << current_section->Name << std::endl;
			return 4;
		}

		if (end_marker_index % 4 != 0 ||
			raw_data_size % 4 != 0)
		{
			std::cout << "[-] invalid shellcode alignment ( != 4 ) " << current_section->Name << std::endl;
			return 4;
		}

		std::cout << "[+] shellcode_size " << std::hex << end_marker_index << std::endl;

		auto context_ptr_value = *(uintptr_t*)(raw_data_ptr + end_marker_index - sizeof(uintptr_t));
		if (context_ptr_value != CONTEXT_DEFAULT_MAGIC_VALUE) {
			std::cout << "[-] failed to verify magic context_ptr value at the end" << std::hex << context_ptr_value << std::endl;
			return 7;
		}

		auto output_file_name_hpp = output_path + "/" + iter->second.name + ".hpp";
		auto output_file_name_bin = output_path + "/" + iter->second.name + ".bin";

		std::ofstream hpp_out_file(output_file_name_hpp, std::ios::trunc);
		if (!hpp_out_file.is_open()) {
			std::cout << "[-] failed to open output file " << output_file_name_hpp << std::endl;
			return 5;
		}

		std::ofstream bin_out_file(output_file_name_bin, std::ios::trunc | std::ios::binary);
		if (!bin_out_file.is_open()) {
			std::cout << "[-] failed to open output file " << output_file_name_bin << std::endl;
			return 5;
		}

		bin_out_file.write((const char*)raw_data_ptr, end_marker_index);
		bin_out_file.close();


		auto write_string = [&](std::string str) -> void {
			hpp_out_file.write(str.data(), str.length());
		};


		int randomkey1 = rand() % 0xFF;
		int randomkey2 = rand() % 0xFF;
		int randomkey3 = rand() % 0xFF;
		int randomkey4 = rand() % 0xFF;
		int randomkey = 0xFFFFFFFF;

		*(((BYTE*)&randomkey) + 0x00) = (BYTE)randomkey1;
		*(((BYTE*)&randomkey) + 0x01) = (BYTE)randomkey2;
		*(((BYTE*)&randomkey) + 0x02) = (BYTE)randomkey3;
		*(((BYTE*)&randomkey) + 0x03) = (BYTE)randomkey4;

		char szRandomKey[30];
		sprintf_s<30>(szRandomKey, "0x%X", randomkey);

		write_string("constexpr unsigned int shKey" + iter->second.name + " = " + std::string(szRandomKey) + ";\n");

		auto raw_data_ptr_encrypted = new uint8_t[raw_data_size];
		memcpy(raw_data_ptr_encrypted, raw_data_ptr, raw_data_size);

		for (int i = 0; i < raw_data_size - 0x4; i+= 0x4) {
			auto ptr = (int*)(raw_data_ptr_encrypted + i);
			*ptr ^= (randomkey + i);
		}


		write_string("static unsigned char sh" + iter->second.name + " [] = {\n");
		int icounter = 0;
		for (int i = 0; i < end_marker_index; i++) {
			char hexbuffer[20] = {};
			memset(hexbuffer, 0, 20);

			sprintf_s<20>(hexbuffer, "0x%02X", raw_data_ptr_encrypted[i]);
			write_string(std::string(hexbuffer));

			if (i != end_marker_index - 1)
				write_string(",");

			icounter++;

			if (icounter % 20 == 0) {
				write_string("\n");
			}
		}
		write_string("};\n\n\n");

		build_helper_functions(iter->second.name, hpp_out_file);

		std::cout << "[+] " << iter->second.name + ".hpp" << " saved successfully" << std::endl;
		iter->second.extracted = true;
	}




	for (auto& fn_s : function_section_map) {
		if (!fn_s.second.extracted) {
			std::cout << "[-] failed to find " << fn_s.second.name  << " in " << fn_s.first << std::endl;
			return 6;
		}
	}

	std::cout << "[+] all done!" << std::endl;
	return 0;
}