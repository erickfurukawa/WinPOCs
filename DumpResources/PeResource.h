#pragma once

#include "..\Common\PE.h"
#include <Windows.h>
#include <string>
#include <memory>
#include <vector>

class PeResource
{
public:
	PeResource() = default;
	PeResource(const PeResource& resource);
	PeResource(WORD type, WORD id, std::wstring idStr, bool idIsStr, WORD language, BYTE* rawData, size_t dataSize);

	BYTE* rawData = nullptr;
	size_t dataSize = 0;

	WORD GetType();
	std::wstring GetTypeStr();
	
	WORD GetId();
	std::wstring GetIdStr();
	bool IsIdStr();

	WORD GetLanguage();
	// TODO: GetLanguageStr()

	static std::vector<PeResource> GetResources(PE& pe);

private:
	WORD type = 0;
	WORD id = 0;
	std::wstring idStr;
	bool idIsStr = false;
	WORD language = 0;

	std::unique_ptr<BYTE[]> rawDataBuffer;
};