#include <windows.h>
#include <memory>
#include <string>
#include <vector>

class Group
{
private:
	std::unique_ptr<BYTE[]> sidBuffer = {0};

public:
	std::wstring groupname = {0};
	std::wstring comment = {0};
	SID* pSid = nullptr;
	std::wstring sidStr = {0};

	Group() = default;
	Group(std::wstring groupname);
};

class User
{
private:
	std::unique_ptr<BYTE[]> sidBuffer = {0};

public:
	std::wstring username = {0};
	SID* pSid = nullptr;
	std::wstring sidStr = {0};
	std::vector<Group> localGroups;

	User() = default;
	User(std::wstring username);

	/*
		Given a handle to an object, the function queries the object's DACL and returns the potential
		access that the user would be able to get when opening a handle to the object.
		The handle must be opened with READ_CONTROL.

		See Remarks from Microsoft documentation for GetEffectiveRightsFromAclW to view the list of
		rights that are not considered. Owner rights are being considered.
	*/ 
	DWORD GetAccessRights(HANDLE handle);
	DWORD GetAccessRights(std::wstring filename);
	static std::vector<User> GetAllUsers();
};