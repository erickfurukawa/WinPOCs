#include <iostream>
#include <fstream>
#include <string.h>
#include <format>
#include "../Common/Constants.h"
#include "../Common/Utils.h"
#include "../Common/PE.h"

namespace 
{
    const char structName[] = "DllInfo";
    bool GenerateCpp(PE* dll)
    {
        bool success = false;
        std::string dllName = std::string(dll->fileName).substr(0, strnlen(dll->fileName, MAX_LENGTH + 1) - 4);

        std::string headerStr;
        std::string structStr;
        std::string setupProxyStr;
        std::string dllMainStr;
        std::string functionsStr;
        std::string freeLibraryStr = std::format("            FreeLibrary({}.handle);\n", structName);

        headerStr = "#include \"pch.h\"";
        headerStr += "#include <windows.h>\n\n";
        headerStr += "void SetupProxy();\n\n";

        structStr = "struct {\n";
        structStr += "    HMODULE handle;\n";

        dllMainStr +=
            "BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)\n"
            "{\n"
            "    switch (ul_reason_for_call)\n"
            "    {\n"
            "        case DLL_PROCESS_ATTACH:\n"
            "        {\n"
            "            SetupProxy();\n"
            "            break;\n"
            "        }\n"
            "        case DLL_THREAD_ATTACH:\n"
            "        case DLL_THREAD_DETACH:\n"
            "        case DLL_PROCESS_DETACH:\n"
            "        {\n" +
                        freeLibraryStr +
            "        }\n"
            "        break;\n"
            "    }\n"
            "    return TRUE;\n"
            "}\n\n";

        setupProxyStr = "void SetupProxy()\n{\n";
        setupProxyStr += std::format("    {}.handle = LoadLibraryA(\"original_{}.dll\");\n", structName, dllName);

        PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
            dll->RVAToBufferPointer(dll->pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

        WORD* pOrdinal = reinterpret_cast<WORD*>(dll->RVAToBufferPointer(pExportDirectory->AddressOfNameOrdinals));
        DWORD* pFuncNameRVA = reinterpret_cast<DWORD*>(dll->RVAToBufferPointer(pExportDirectory->AddressOfNames));

        for (int i = 0; i < pExportDirectory->NumberOfNames; i++)
        {
            if (*pFuncNameRVA)
            {
                // TODO: forwarder RVA 
                // TODO: x64
                std::string funcName = std::string(reinterpret_cast<char*>(dll->RVAToBufferPointer(*pFuncNameRVA)));
                std::string origFuncName = "original_" + funcName;
                std::string proxyFuncName = "proxy_" + funcName;

                structStr += std::format("    FARPROC {};\n", origFuncName);
                setupProxyStr += std::format("    {}.{} = GetProcAddress({}.handle, \"{}\");\n", structName, origFuncName, structName, funcName);
                functionsStr += std::format("__declspec(naked) void {}() {{ _asm {{ jmp [{}.{}] }} }};\n", proxyFuncName, structName, origFuncName);
            }
            else
            {
                // TODO: export by ordinal. change NumberOfNames to NumberOfFunctions
            }
            pOrdinal++;
            pFuncNameRVA++;
        }
        structStr += std::format("}} {};\n\n", structName);
        setupProxyStr += "}\n\n";

        std::string filename = dllName + ".cpp";
        std::ofstream cppFile;
        cppFile.open(filename);

        if (cppFile.is_open())
        {
            cppFile << headerStr;
            cppFile << structStr;
            cppFile << dllMainStr;
            cppFile << setupProxyStr;
            cppFile << functionsStr;

            cppFile.close();
            success = true;
        }
        else
        {
            std::cerr << "Could not create cpp file: " << filename << "\n";
            success = false;
        }

        return success;
    }

    bool GenerateDef(PE* dll)
    {
        bool success = false;
        std::string dllName = std::string(dll->fileName).substr(0, strnlen(dll->fileName, MAX_LENGTH+1)-4);
        std::string filename = dllName + ".def";
        std::ofstream defFile;
        defFile.open(filename);

        if (defFile.is_open())
        {
            defFile << std::format("LIBRARY {}\n", dllName) ;
            defFile << "EXPORTS\n";
            PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
                dll->RVAToBufferPointer(dll->pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

            WORD* pOrdinal = reinterpret_cast<WORD*>(dll->RVAToBufferPointer(pExportDirectory->AddressOfNameOrdinals));
            DWORD* pFuncNameRVA = reinterpret_cast<DWORD*>(dll->RVAToBufferPointer(pExportDirectory->AddressOfNames));

            for (int i = 0; i < pExportDirectory->NumberOfNames; i++) 
            {
                if (*pFuncNameRVA)
                {
                    // TODO: forwarder RVA 
                    std::string funcName = std::string(reinterpret_cast<char*>(dll->RVAToBufferPointer(*pFuncNameRVA)));
                    defFile << std::format("\t{} = {} @{}\n", funcName, "proxy_"+funcName, *pOrdinal + pExportDirectory->Base);
                }
                else
                {
                    // TODO: export by ordinal. change NumberOfNames to NumberOfFunctions
                }
                pOrdinal++;
                pFuncNameRVA++;
            }

            defFile.close();
            success = true;
        }
        else 
        {
            std::cerr << "Could not create definition file: " << filename << "\n";
            success = false;
        }

        return success;
    }
}

int main(int argc, char** argv)
{
    char dllPath[MAX_PATH + 1];

    if (argc == 2) {
        strncpy_s(dllPath, argv[1], MAX_PATH + 1);
    }
    else {
        std::cout << "Dll path:\n";
        std::cin.getline(dllPath, MAX_PATH + 1);
    }

    if (!FileExists(dllPath))
    {
        std::cerr << "Could not open dll " << dllPath << "\n";
        return 1;
    }

    PE* dll = new PE(dllPath);
    GenerateDef(dll);
    GenerateCpp(dll);
    delete dll;
}
