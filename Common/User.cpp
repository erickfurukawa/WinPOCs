#include "User.h"
#include "Utils.h"
#include <Lm.h>
#include <sddl.h>
#include <iostream>
#include <aclapi.h>

#pragma comment(lib, "netapi32.lib")

namespace
{
	std::wstring SIDToString(PSID pSid)
	{
		wchar_t* sidStrc = nullptr;
		ConvertSidToStringSidW(pSid, &sidStrc);
		std::wstring sidStr = std::wstring(sidStrc);
		LocalFree(sidStrc);
		return sidStr;
	}

	bool LookupName(const wchar_t* name, std::unique_ptr<BYTE[]>& sidBuffer, std::wstring& refDomainName, SID_NAME_USE& type)
	{
		bool success = false;
		DWORD sidSize = 0, domainSize = 0;
		LookupAccountNameW(0, name, 0, &sidSize, 0, &domainSize, &type);
		sidBuffer = std::make_unique<BYTE[]>(sidSize);
		auto domainBuffer = std::make_unique<wchar_t[]>(domainSize);
		if (LookupAccountNameW(nullptr, name, sidBuffer.get(), &sidSize, domainBuffer.get(), &domainSize, &type))
		{
			refDomainName = std::wstring(domainBuffer.get());
			success = true;
		}
		else
		{
			std::wcerr << L"LookupAccountNameW error: " << name << std::endl;
		}
		return success;
	}
}

User::User(std::wstring username)
{
	this->username = username;

	// get user info -----------------------------------
	USER_INFO_23* pUserInfo23 = nullptr;
	wchar_t* sidStr = nullptr;
	if (NetUserGetInfo(nullptr, username.c_str(), 23, reinterpret_cast<LPBYTE*>(&pUserInfo23)) != NERR_Success)
	{
		ThrowException(std::string("Could not find user: ") + ToStringUTF8(username));
	}
	// copy sid from structure to member variables
	DWORD sidSize = GetLengthSid(pUserInfo23->usri23_user_sid);
	this->sidBuffer = std::make_unique<BYTE[]>(sidSize);
	this->pSid = reinterpret_cast<SID*>(sidBuffer.get());
	CopySid(sidSize, this->pSid, pUserInfo23->usri23_user_sid);
	this->sidStr = SIDToString(pUserInfo23->usri23_user_sid);
	NetApiBufferFree(pUserInfo23);

	// get user groups -----------------------------------
	LOCALGROUP_USERS_INFO_0* pGroupInfo1 = nullptr;
	DWORD entriesRead, totalEntries;
	if (NetUserGetLocalGroups(nullptr, username.c_str(), 0, LG_INCLUDE_INDIRECT, reinterpret_cast<LPBYTE*>(&pGroupInfo1), MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries) != NERR_Success)
	{
		ThrowException(std::string("Could not get group info of user: ") + ToStringUTF8(username));
	}
	for (unsigned int i = 0; i < entriesRead; i++)
	{
		this->localGroups.push_back(Group(pGroupInfo1[i].lgrui0_name));
	}
	NetApiBufferFree(pGroupInfo1);
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

DWORD User::GetAccessRights(HANDLE handle)
{
	DWORD access = 0, ownerAccess = 0;
	PSECURITY_DESCRIPTOR pSecDesc;
	PSID pSidOwner;
	PACL pDacl;

	if (GetSecurityInfo(handle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, &pSidOwner, nullptr, &pDacl, nullptr, &pSecDesc) != ERROR_SUCCESS)
	{
		std::wcerr << L"GetSecurityInfo error\n";
		return 0;
	}

	// create user trustee structure
	TRUSTEE_W trustee = { 0 };
	trustee.TrusteeForm = TRUSTEE_IS_SID;
	trustee.TrusteeType = TRUSTEE_IS_USER;
	trustee.ptstrName = reinterpret_cast<LPWCH>(this->pSid); // would be better to use trustee.pSid, but for some reason the union is not defined.

	// check owner always granted accesses
	BYTE ownerDaclBuffer[0x100] = { 0 };
	PACL pOwnerDacl = reinterpret_cast<PACL>(ownerDaclBuffer);
	InitializeAcl(pOwnerDacl, 0x100, ACL_REVISION);
	AddAccessAllowedAce(pOwnerDacl, ACL_REVISION, READ_CONTROL | WRITE_DAC, pSidOwner);
	DWORD status = GetEffectiveRightsFromAclW(pOwnerDacl, &trustee, &ownerAccess);
	if (status != ERROR_SUCCESS)
	{
		std::wcerr << L"GetEffectiveRightsFromAclW owner access error\n";
		return 0;
	}

	// check dacl accesses
	status = GetEffectiveRightsFromAclW(pDacl, &trustee, &access);
	LocalFree(pSecDesc);
	if (status != ERROR_SUCCESS)
	{
		std::wcerr << L"GetEffectiveRightsFromAclW error\n";
		return 0;
	}
	return access | ownerAccess;
}

DWORD User::GetAccessRights(std::wstring filename)
{
	// try to open file
	HANDLE handle = CreateFileW(filename.c_str(), READ_CONTROL, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		// try to open directory
		handle = CreateFileW(filename.c_str(), READ_CONTROL, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
		if (handle == INVALID_HANDLE_VALUE)
		{
			std::wcerr << "Could open file or directory " << filename.c_str() << std::endl;
			return 0;
		}
	}
	DWORD access = this->GetAccessRights(handle);
	CloseHandle(handle);
	return access;
}

Group::Group(std::wstring groupname)
{
	this->groupname = groupname;

	LOCALGROUP_INFO_1* pGroupInfo3 = nullptr;
	wchar_t* sidStr = nullptr;

	if (NetLocalGroupGetInfo(nullptr, groupname.c_str(), 1, reinterpret_cast<LPBYTE*>(&pGroupInfo3)) == NERR_Success)
	{
		this->groupname = pGroupInfo3->lgrpi1_name;
		this->comment = pGroupInfo3->lgrpi1_comment;
	}
	else
	{
		ThrowException(std::string("Could not find group: ") + ToStringUTF8(groupname));
	}

	SID_NAME_USE type = SID_NAME_USE::SidTypeUser;
	std::wstring refDomain;
	if (LookupName(this->groupname.c_str(), this->sidBuffer, refDomain, type))
	{
		this->pSid = reinterpret_cast<SID*>(this->sidBuffer.get());
		this->sidStr = SIDToString(sidBuffer.get());
	}
	else
	{
		ThrowException(std::string("LookupName error: ") + ToStringUTF8(groupname));
	}
}