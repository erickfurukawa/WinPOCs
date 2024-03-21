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

	static std::vector<User> GetAllUsers();
};