#include "ioctl_base.hpp"

#include <winioctl.h>
#include <nvme.h>

#define BufferSize 4096
char storage_query_buf[BufferSize] = { 0 };

void storage_query_property::trigger()
{
	// PropertyStandardQuery
	{
		STORAGE_PROPERTY_QUERY query;
		memset(&query, 0, sizeof(query));
		query.PropertyId = StorageDeviceProperty;
		query.QueryType = PropertyStandardQuery;
		memset(storage_query_buf, 0, sizeof(storage_query_buf));

        set_id("StorageDeviceProperty");
		if (send_ioctl(&query, sizeof(query), storage_query_buf, sizeof(storage_query_buf)))
		{
			auto desc = (STORAGE_DEVICE_DESCRIPTOR*)storage_query_buf;
			auto serial = ((char*)desc + desc->SerialNumberOffset);
			print_serial(serial);
		}
	}

    // StorageAdapterProtocolSpecificProperty
    {
        BOOL    result;
        PVOID   buffer = NULL;
        ULONG   bufferLength = 0;
        ULONG   returnedLength = 0;

        PSTORAGE_PROPERTY_QUERY query = NULL;
        PSTORAGE_PROTOCOL_SPECIFIC_DATA protocolData = NULL;
        PSTORAGE_PROTOCOL_DATA_DESCRIPTOR protocolDataDescr = NULL;

        //
        // Allocate buffer for use.
        //
        bufferLength = FIELD_OFFSET(STORAGE_PROPERTY_QUERY, AdditionalParameters) + sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) + NVME_MAX_LOG_SIZE;
        buffer = malloc(bufferLength);


        //
        // Initialize query data structure to get Identify Controller Data.
        //
        ZeroMemory(buffer, bufferLength);

        query = (PSTORAGE_PROPERTY_QUERY)buffer;
        protocolDataDescr = (PSTORAGE_PROTOCOL_DATA_DESCRIPTOR)buffer;
        protocolData = (PSTORAGE_PROTOCOL_SPECIFIC_DATA)query->AdditionalParameters;

        query->PropertyId = StorageAdapterProtocolSpecificProperty;
        query->QueryType = PropertyStandardQuery;

        protocolData->ProtocolType = ProtocolTypeNvme;
        protocolData->DataType = NVMeDataTypeIdentify;
        protocolData->ProtocolDataRequestValue = NVME_IDENTIFY_CNS_CONTROLLER;
        protocolData->ProtocolDataRequestSubValue = 0;
        protocolData->ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
        protocolData->ProtocolDataLength = NVME_MAX_LOG_SIZE;

        set_id("StorageAdapterProtocolSpecificProperty");
        if (send_ioctl(buffer, bufferLength, buffer, bufferLength))
        {
            auto nvme_data = (PNVME_IDENTIFY_CONTROLLER_DATA)((PCHAR)protocolData + protocolData->ProtocolDataOffset);
            std::string serial((char*)nvme_data->SN, 20);
            print_serial(serial);
        }

        free(buffer);
    }

    //// StorageDeviceProtocolSpecificProperty
    //{
    //    BOOL    result;
    //    PVOID   buffer = NULL;
    //    ULONG   bufferLength = 0;
    //    ULONG   returnedLength = 0;

    //    PSTORAGE_PROPERTY_QUERY query = NULL;
    //    PSTORAGE_PROTOCOL_SPECIFIC_DATA protocolData = NULL;
    //    PSTORAGE_PROTOCOL_DATA_DESCRIPTOR protocolDataDescr = NULL;

    //    //
    //    // Allocate buffer for use.
    //    //
    //    bufferLength = FIELD_OFFSET(STORAGE_PROPERTY_QUERY, AdditionalParameters) + sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) + NVME_MAX_LOG_SIZE;
    //    buffer = malloc(bufferLength);


    //    //
    //    // Initialize query data structure to get Identify Controller Data.
    //    //
    //    ZeroMemory(buffer, bufferLength);

    //    query = (PSTORAGE_PROPERTY_QUERY)buffer;
    //    protocolDataDescr = (PSTORAGE_PROTOCOL_DATA_DESCRIPTOR)buffer;
    //    protocolData = (PSTORAGE_PROTOCOL_SPECIFIC_DATA)query->AdditionalParameters;

    //    query->PropertyId = StorageDeviceProtocolSpecificProperty;
    //    query->QueryType = PropertyStandardQuery;

    //    protocolData->ProtocolType = ProtocolTypeNvme;
    //    protocolData->DataType = NVMeDataTypeIdentify;
    //    protocolData->ProtocolDataRequestValue = NVME_IDENTIFY_CNS_CONTROLLER;
    //    protocolData->ProtocolDataRequestSubValue = 0;
    //    protocolData->ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
    //    protocolData->ProtocolDataLength = NVME_MAX_LOG_SIZE;

    //    set_id("StorageDeviceProtocolSpecificProperty");
    //    if (send_ioctl(buffer, bufferLength, buffer, bufferLength))
    //    {
    //        auto nvme_data = (PNVME_IDENTIFY_CONTROLLER_DATA)((PCHAR)protocolData + protocolData->ProtocolDataOffset);
    //        std::string serial((char*)nvme_data->SN, 20);
    //        print_serial(serial);
    //    }

    //    free(buffer);
    //}

}