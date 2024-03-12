#include <windows.h>
#include <memory>
#include <string>
#include <vector>

class User
{
private:
	std::unique_ptr<BYTE[]> sidBuffer = {0};

public:
	std::wstring username = {0};
	SID* pSid = nullptr;
	std::wstring sidStr = {0};

	User() = default;
	User(std::wstring username);

	static std::vector<User> GetAllUsers();
};