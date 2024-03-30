#include "PeResource.h"
#include <map>

namespace
{
	//https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types
	std::map<ULONG_PTR, std::wstring> typeMap
	{
		{(ULONG_PTR)RT_ACCELERATOR, std::wstring(L"RT_ACCELERATOR")},
		{(ULONG_PTR)RT_ANICURSOR, std::wstring(L"RT_ANICURSOR")},
		{(ULONG_PTR)RT_ANIICON, std::wstring(L"RT_ANIICON")},
		{(ULONG_PTR)RT_BITMAP, std::wstring(L"RT_BITMAP")},
		{(ULONG_PTR)RT_CURSOR, std::wstring(L"RT_CURSOR")},
		{(ULONG_PTR)RT_DIALOG, std::wstring(L"RT_DIALOG")},
		{(ULONG_PTR)RT_DLGINCLUDE, std::wstring(L"RT_DLGINCLUDE")},
		{(ULONG_PTR)RT_FONT, std::wstring(L"RT_FONT")},
		{(ULONG_PTR)RT_FONTDIR, std::wstring(L"RT_FONTDIR")},
		{(ULONG_PTR)RT_GROUP_CURSOR, std::wstring(L"RT_GROUP_CURSOR")},
		{(ULONG_PTR)RT_GROUP_ICON, std::wstring(L"RT_GROUP_ICON")},
		{(ULONG_PTR)RT_HTML, std::wstring(L"RT_HTML")},
		{(ULONG_PTR)RT_ICON, std::wstring(L"RT_ICON")},
		{(ULONG_PTR)RT_MANIFEST, std::wstring(L"RT_MANIFEST")},
		{(ULONG_PTR)RT_MENU, std::wstring(L"RT_MENU")},
		{(ULONG_PTR)RT_MESSAGETABLE, std::wstring(L"RT_MESSAGETABLE")},
		{(ULONG_PTR)RT_PLUGPLAY, std::wstring(L"RT_PLUGPLAY")},
		{(ULONG_PTR)RT_RCDATA, std::wstring(L"RT_RCDATA")},
		{(ULONG_PTR)RT_STRING, std::wstring(L"RT_STRING")},
		{(ULONG_PTR)RT_VERSION, std::wstring(L"RT_VERSION")},
		{(ULONG_PTR)RT_VXD, std::wstring(L"RT_VXD")}
	};

	unsigned int GetTableNumberOfEntries(IMAGE_RESOURCE_DIRECTORY* table)
	{
		return table->NumberOfIdEntries + table->NumberOfNamedEntries;
	}

	PIMAGE_RESOURCE_DIRECTORY_ENTRY GetTableEntry(IMAGE_RESOURCE_DIRECTORY* table, unsigned int index)
	{
		PIMAGE_RESOURCE_DIRECTORY_ENTRY pFirstTableEntry = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(reinterpret_cast<BYTE*>(table) + sizeof(IMAGE_RESOURCE_DIRECTORY));
		return &pFirstTableEntry[index];
	}
}

PeResource::PeResource(const PeResource& resource)
{
	this->type = resource.type;
	this->idIsStr = resource.idIsStr;
	this->id = resource.id;
	this->idStr = resource.idStr;
	this->language = resource.language;
	
	// copy data
	this->dataSize = resource.dataSize;
	this->rawDataBuffer = std::make_unique<BYTE[]>(this->dataSize);
	memcpy(this->rawDataBuffer.get(), resource.rawData, resource.dataSize);
	this->rawData = this->rawDataBuffer.get();
}

PeResource::PeResource(WORD type, WORD id, std::wstring idStr, bool idIsStr, WORD language, BYTE* rawData, size_t dataSize)
{
	this->type = type;
	this->idIsStr = idIsStr;
	if (idIsStr)
	{
		this->idStr = idStr;
		this->id = 0;
	}
	else
	{
		this->id = id;
		this->idStr = L"ID(" + std::to_wstring(id) + L")";
	}
	this->rawDataBuffer = std::make_unique<BYTE[]>(dataSize);
	this->dataSize = dataSize;
	memcpy(this->rawDataBuffer.get(), rawData, dataSize);
	this->rawData = this->rawDataBuffer.get();

	this->language = language;
}

WORD PeResource::GetType()
{
	return this->type;
}

std::wstring PeResource::GetTypeStr()
{
	if (typeMap.count(this->type) > 0)
	{
		return typeMap[this->type];
	}
	return L"ID(" + std::to_wstring(this->type) + L")";
}

WORD PeResource::GetId()
{
	return this->id;
}

std::wstring PeResource::GetIdStr()
{
	return this->idStr;
}

bool PeResource::IsIdStr()
{
	return this->idIsStr;
}

WORD PeResource::GetLanguage()
{
	return this->language;
}

std::vector<PeResource> PeResource::GetResources(PE& pe)
{
	std::vector<PeResource> resources;

	DWORD rva = pe.pDataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	BYTE* baseAddr = pe.RVAToBufferPointer(rva);

	IMAGE_RESOURCE_DIRECTORY* pTypeTable = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(baseAddr);
	unsigned int numTypeTableEntries = GetTableNumberOfEntries(pTypeTable);
	for (unsigned int typeIndex = 0; typeIndex < numTypeTableEntries; typeIndex++)
	{
		// Type level entries
		IMAGE_RESOURCE_DIRECTORY_ENTRY* pTypeTableEntry = GetTableEntry(pTypeTable, typeIndex);
		IMAGE_RESOURCE_DIRECTORY* pNameTable = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(baseAddr + pTypeTableEntry->OffsetToDirectory);
		unsigned int numNameTableEntries = GetTableNumberOfEntries(pNameTable);
		for (unsigned int nameIndex = 0; nameIndex < numNameTableEntries; nameIndex++)
		{
			// Name level entries
			IMAGE_RESOURCE_DIRECTORY_ENTRY* pNameTableEntry = GetTableEntry(pNameTable, nameIndex);
			IMAGE_RESOURCE_DIRECTORY* pLanguageTable = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(baseAddr + pNameTableEntry->OffsetToDirectory);
			unsigned int numLanguageTableEntries = GetTableNumberOfEntries(pLanguageTable);

			for (unsigned int languageIndex = 0; languageIndex < numLanguageTableEntries; languageIndex++)
			{
				// Language level entries and resource data
				IMAGE_RESOURCE_DIRECTORY_ENTRY* pLanguageTableEntry = GetTableEntry(pLanguageTable, languageIndex);
				IMAGE_RESOURCE_DATA_ENTRY* pResourceData = reinterpret_cast<IMAGE_RESOURCE_DATA_ENTRY*>(baseAddr + pLanguageTableEntry->OffsetToData);
				
				// create resource
				BYTE* dataPtr = pe.RVAToBufferPointer(pResourceData->OffsetToData);
				size_t dataSize = pResourceData->Size;
				if (pNameTableEntry->NameIsString)
				{
					WORD strLen = *(reinterpret_cast<WORD*>(baseAddr + pNameTableEntry->NameOffset));
					WCHAR* strPtr = reinterpret_cast<WCHAR*>(baseAddr + pNameTableEntry->NameOffset + sizeof(WORD));
					std::wstring name = std::wstring(strPtr, strLen);
					PeResource resource(pTypeTableEntry->Id, 0, name, true, pLanguageTableEntry->Id, dataPtr, dataSize);
					resources.push_back(resource);
				}
				else
				{
					PeResource resource(pTypeTableEntry->Id, pNameTableEntry->Id, L"", false, pLanguageTableEntry->Id, dataPtr, dataSize);
					resources.push_back(resource);
				}
			}
		}
	}

	return resources;
}
