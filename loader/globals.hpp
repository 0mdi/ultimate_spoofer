#pragma once
#include <string>

class globals
{
private:
	globals() {}

public:
	static globals* instance()
	{
		static globals* ptr = nullptr;
		if (!ptr)
			ptr = new globals();
		return ptr;
	}

	std::string application_name;
	std::string application_path;
	std::string driver_name;
	std::string driver_path;
};