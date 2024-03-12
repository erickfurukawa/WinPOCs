#include "User.h"
#include "Utils.h"
#include <Lm.h>
#include <sddl.h>

#pragma comment(lib, "netapi32.lib")

User::User(std::wstring username)
{
	this->username = username;

	USER_INFO_23* pUserInfo23 = nullptr;
	wchar_t* sidStr = nullptr;
	if (NetUserGetInfo(nullptr, username.c_str(), 23, reinterpret_cast<LPBYTE*>(&pUserInfo23)) == NERR_Success)
	{
		// copy sid from structure to member variables
		DWORD sidSize = GetLengthSid(pUserInfo23->usri23_user_sid);
		this->sidBuffer = std::make_unique<BYTE[]>(sidSize);
		this->pSid = reinterpret_cast<SID*>(sidBuffer.get());
		CopySid(sidSize, this->pSid, pUserInfo23->usri23_user_sid);

		ConvertSidToStringSidW(pUserInfo23->usri23_user_sid, &sidStr);
		this->sidStr = std::wstring(sidStr);
		LocalFree(sidStr);

		NetApiBufferFree(pUserInfo23);
	}
	else
	{
		ThrowException(std::string("Could not find user: ") + ToStringUTF8(username));
	}
}

std::vector<User> User::GetAllUsers()
{
	std::vector<User> users;

	USER_INFO_0* pUserInfo = nullptr;
	DWORD entriesRead, totalEntries;
	DWORD hResume = 0;
	std::vector<std::wstring> usernames;

	NET_API_STATUS status = NetUserEnum(nullptr, 0, 0, reinterpret_cast<LPBYTE*>(&pUserInfo), MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &hResume);
	if (status == NERR_Success)
	{
		for (unsigned int i = 0; i < entriesRead; i++)
		{
			usernames.push_back(std::wstring(pUserInfo[i].usri0_name));
		}
		NetApiBufferFree(pUserInfo);
	}
	else
	{
		ThrowException(std::string("Could not enumerate users"));
	}

	for (std::wstring username : usernames)
	{
		users.push_back(User(username));
	}
	return users;
}