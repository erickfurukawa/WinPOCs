#include "DumpResources.h"
#include <iostream>
#include <fstream>
#include <map>

namespace
{
	std::wstring IdToName(WORD id)
	{
		//https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types
		std::map<ULONG_PTR, std::wstring> idMap
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
			{(ULONG_PTR)RT_ACCELERATOR, std::wstring(L"RT_ACCELERATOR")},
			{(ULONG_PTR)RT_MANIFEST, std::wstring(L"RT_MANIFEST")},
			{(ULONG_PTR)RT_MENU, std::wstring(L"RT_MENU")},
			{(ULONG_PTR)RT_MESSAGETABLE, std::wstring(L"RT_MESSAGETABLE")},
			{(ULONG_PTR)RT_PLUGPLAY, std::wstring(L"RT_PLUGPLAY")},
			{(ULONG_PTR)RT_RCDATA, std::wstring(L"RT_RCDATA")},
			{(ULONG_PTR)RT_STRING, std::wstring(L"RT_STRING")},
			{(ULONG_PTR)RT_VERSION, std::wstring(L"RT_VERSION")},
			{(ULONG_PTR)RT_VXD, std::wstring(L"RT_VXD")}
		};

		if (idMap.contains(id))
		{
			return idMap[id] + L"(" + std::to_wstring(id) + L")";
		}
		return L"ID(" + std::to_wstring(id) + L")";
	}

	unsigned int GetTableNumberOfEntries(IMAGE_RESOURCE_DIRECTORY* table)
	{
		return table->NumberOfIdEntries + table->NumberOfNamedEntries;
	}

	PIMAGE_RESOURCE_DIRECTORY_ENTRY GetTableEntry(IMAGE_RESOURCE_DIRECTORY* table, unsigned int index)
	{
		PIMAGE_RESOURCE_DIRECTORY_ENTRY pFirstTableEntry = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(reinterpret_cast<BYTE*>(table) + sizeof(IMAGE_RESOURCE_DIRECTORY));
		return &pFirstTableEntry[index];
	}
	
	std::wstring GetEntryNameOrID(BYTE* baseAddress, IMAGE_RESOURCE_DIRECTORY_ENTRY* entry, bool resolveType = false)
	{
		std::wstring name{};
		if (entry->NameIsString)
		{
			WORD strLen = *(reinterpret_cast<WORD*>(baseAddress + entry->NameOffset));
			WCHAR* strPtr = reinterpret_cast<WCHAR*>(baseAddress + entry->NameOffset + sizeof(WORD));
			name = std::wstring(strPtr, strLen);
		}
		else // Name is ID
		{
			if (resolveType)
			{
				name = IdToName(entry->Id);
			}
			else // resolve language?
			{
				return L"ID(" + std::to_wstring(entry->Id) + L")";
			}
		}
		return name;
	}
}

bool DumpResources(PE& pe)
{
	int currentItem = 0;
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

				// get resource name
				std::wstring typeName = GetEntryNameOrID(baseAddr, pTypeTableEntry, true);
				std::wstring nameName = GetEntryNameOrID(baseAddr, pNameTableEntry);
				std::wstring languageName = GetEntryNameOrID(baseAddr, pLanguageTableEntry);
				std::wcout << currentItem  << L" - " << typeName << L" - " << nameName << " - " << languageName << std::endl;

				// dump file
				std::string fileName = "Dump " + std::to_string(currentItem);
				std::ofstream fileDump(fileName.c_str(), std::ios::out | std::ios::binary);
				fileDump.write(reinterpret_cast<char *>(pe.RVAToBufferPointer(pResourceData->OffsetToData)), pResourceData->Size);
				fileDump.close();

				currentItem++;
			}
		}
	}

	return true;
}