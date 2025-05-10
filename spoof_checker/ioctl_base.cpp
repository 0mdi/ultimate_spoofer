#include "ioctl_base.hpp"
#include "color.hpp"
#include <iostream>
#include <Windows.h>

bool ioctl_base::send_ioctl(void* in_buf, size_t in_len, void* out_buf, size_t out_len)
{
	DWORD bytes_returned = 0;
	if (!DeviceIoControl(m_device, m_ioctl_code, in_buf, in_len, out_buf, out_len, &bytes_returned, nullptr))
	{
		print_error(GetLastError());
		return false;
	}
	return true;
}

void ioctl_base::set_id(std::string id)
{
	m_id = id;
}

void ioctl_base::print_serial(std::string serial, std::string id)
{
	if (id.empty() && !m_id.empty())
		id = m_id;

	if (id.empty())
		std::cout << "[" << dye::purple(m_ioctl_name.c_str()) << "] serial: " << dye::green(serial) << std::endl;
	else
		std::cout << "[" << dye::purple(m_ioctl_name.c_str()) << " -> " << dye::aqua(id) << "] serial: " << dye::green(serial) << std::endl;
}

void ioctl_base::print_error(uint32_t error_code)
{
	if (m_id.empty())
		std::cout << "[" << dye::purple(m_ioctl_name.c_str()) << "] " << dye::red("ERROR ") << error_code << std::endl;
	else
		std::cout << "[" << dye::purple(m_ioctl_name.c_str()) << " -> " << dye::aqua(m_id) << "] " << dye::red("ERROR ") << error_code << std::endl;
}