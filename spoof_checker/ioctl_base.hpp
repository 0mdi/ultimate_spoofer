#pragma once
#include <Windows.h>
#include <stdint.h>
#include <string>
#include <ntddscsi.h>

//#define SMART_RCV_DRIVE_DATA            CTL_CODE(IOCTL_DISK_BASE, 0x0022, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

class ioctl_base
{
public:
	virtual void trigger() = 0;
protected:
	ioctl_base(void* device, uint32_t code, std::string name)
		:	m_device(device),
			m_ioctl_code(code),
			m_ioctl_name(name)
	{}

	bool send_ioctl(void* in_buf, size_t in_len, void* out_buf, size_t out_len);

	void set_id(std::string id);
	void print_serial(std::string serial, std::string id = "");
	void print_error(uint32_t error_code);

	uint32_t m_ioctl_code;
	void* m_device;
	std::string m_ioctl_name;
	std::string m_id;
};

class smart_rcv_drive_data : public ioctl_base
{
public:
	smart_rcv_drive_data(void* device) 
		: ioctl_base(device, SMART_RCV_DRIVE_DATA, "SMART_RCV_DRIVE_DATA")
	{}
	void trigger();
};

class storage_query_property : public ioctl_base
{
public:
		storage_query_property(void* device)
		: ioctl_base(device, IOCTL_STORAGE_QUERY_PROPERTY, "IOCTL_STORAGE_QUERY_PROPERTY")
	{}
	void trigger();
};

class scsi_miniport : public ioctl_base
{
public:
	scsi_miniport(void* device, uint8_t drive)
		: ioctl_base(device, IOCTL_SCSI_MINIPORT, "IOCTL_SCSI_MINIPORT"),
		  m_drive(drive)
	{}
	void trigger();

private:
	uint8_t m_drive;
};

class ata_pass_through : public ioctl_base
{
public:
	ata_pass_through(void* device)
		: ioctl_base(device, IOCTL_ATA_PASS_THROUGH, "IOCTL_ATA_PASS_THROUGH")
	{}
	void trigger();
};