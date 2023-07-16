#include <iostream>
#include <fstream>
#include <string.h>
#include <vector>
#include <format>
#include "../Common/Constants.h"
#include "../Common/PE.h"
#include "ProxyDllGenerator.h"

namespace 
{
    typedef struct
    {
        std::string funcName;
        DWORD ordinal;
    } Export;
    const char structName[] = "DllInfo";

    std::vector<Export> GetExports(PE& dll)
    {
        std::vector<Export> exports;
        PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
            dll.RVAToBufferPointer(dll.pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

        WORD* pOrdinal = reinterpret_cast<WORD*>(dll.RVAToBufferPointer(pExportDirectory->AddressOfNameOrdinals));
        DWORD* pFuncNameRVA = reinterpret_cast<DWORD*>(dll.RVAToBufferPointer(pExportDirectory->AddressOfNames));
        for (int i = 0; i < pExportDirectory->NumberOfNames; i++)
        {
            if (*pFuncNameRVA)
            {
                // TODO: forwarder RVA 
                std::string funcName = std::string(reinterpret_cast<char*>(dll.RVAToBufferPointer(*pFuncNameRVA)));
                exports.push_back(Export{funcName, *pOrdinal + pExportDirectory->Base});
            }
            else
            {
                // TODO: export by ordinal. change NumberOfNames to NumberOfFunctions
            }
            pOrdinal++;
            pFuncNameRVA++;
        }
        return exports;
    }

    bool GenerateAsm(std::vector<Export> exports, std::string dllName)
    {
        bool success = false;

        // file contents
        std::string publicStr = "";
        std::string dataStr = ".data\n";
        std::string codeStr = ".code\n";

        for (Export exp : exports)
        {
            std::string origFuncName = "original_" + exp.funcName;
            std::string proxyFuncName = "proxy_" + exp.funcName;

            publicStr += std::format("PUBLIC {}\n", origFuncName);
            dataStr += std::format("    {} QWORD 0\n", origFuncName);
            codeStr += std::format("{} PROC\n", proxyFuncName);
            codeStr += std::format("    jmp [{}]\n", origFuncName);
            codeStr += std::format("{} ENDP\n\n", proxyFuncName);
        }
        publicStr += "\n";
        dataStr += "\n";
        codeStr += "END";

        // write file
        std::string filename = dllName + ".asm";
        std::ofstream asmFile;
        asmFile.open(filename);

        if (asmFile.is_open())
        {
            asmFile << publicStr;
            asmFile << dataStr;
            asmFile << codeStr;

            asmFile.close();
            success = true;
        }
        else
        {
            std::cerr << "Could not create asm file: " << filename << "\n";
            success = false;
        }

        return success;
    }

    bool GenerateCpp(std::vector<Export> exports, std::string dllName, bool is32Bits)
    {
        bool success = false;

        // file contents
        std::string headerStr;
        headerStr = "#include \"pch.h\"\n";
        headerStr += "#include <windows.h>\n\n";
        headerStr += "void SetupProxy();\n\n";

        std::string structStr;
        structStr = "struct {\n";
        structStr += "    HMODULE handle;\n";

        std::string setupProxyStr;
        setupProxyStr = "void SetupProxy()\n{\n";
        setupProxyStr += std::format("    {}.handle = LoadLibraryA(\"original_{}.dll\");\n", structName, dllName);

        std::string dllMainStr;
        std::string freeLibraryStr = std::format("            FreeLibrary({}.handle);\n", structName);
        dllMainStr +=
            "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)\n"
            "{\n"
            "    switch (ul_reason_for_call)\n"
            "    {\n"
            "        case DLL_PROCESS_ATTACH:\n"
            "        {\n"
            "            SetupProxy();\n"
            "            break;\n"
            "        }\n"
            "        case DLL_THREAD_ATTACH:\n"
            "            break;\n"
            "        case DLL_THREAD_DETACH:\n"
            "            break;\n"
            "        case DLL_PROCESS_DETACH:\n"
            "        {\n" +
                         freeLibraryStr +
            "            break;\n"
            "        }\n"
            "    }\n"
            "    return TRUE;\n"
            "}\n\n";

        std::string functionsStr;
 
        for (Export exp : exports)
        {
            std::string origFuncName = "original_" + exp.funcName;
            std::string proxyFuncName = "proxy_" + exp.funcName;

            if (is32Bits)
            {
                structStr += std::format("    FARPROC {};\n", origFuncName);
                functionsStr += std::format("__declspec(naked) void {}() {{ _asm {{ jmp [{}.{}] }} }};\n", proxyFuncName, structName, origFuncName);
                setupProxyStr += std::format("    {}.{} = GetProcAddress({}.handle, \"{}\");\n", structName, origFuncName, structName, exp.funcName);
            }
            else
            {
                functionsStr += std::format("extern \"C\" FARPROC {};\n", origFuncName);
                setupProxyStr += std::format("    {} = GetProcAddress({}.handle, \"{}\");\n", origFuncName, structName, exp.funcName);
            }
        }
        structStr += std::format("}} {};\n\n", structName);
        setupProxyStr += "}\n\n";
        functionsStr += "\n";

        // write file
        std::string filename = dllName + ".cpp";
        std::ofstream cppFile;
        cppFile.open(filename);

        if (cppFile.is_open())
        {
            cppFile << headerStr;
            cppFile << structStr;
            cppFile << dllMainStr;
            cppFile << functionsStr;
            cppFile << setupProxyStr;    

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

    bool GenerateDef(std::vector<Export> exports, std::string dllName)
    {
        bool success = false;

        std::string filename = dllName + ".def";
        std::string defStr;

        // file contents
        defStr = std::format("LIBRARY {}\n", dllName);
        defStr += "EXPORTS\n";
        for (Export exp : exports)
        {
            defStr += std::format("\t{} = {} @{}\n", exp.funcName, "proxy_" + exp.funcName, exp.ordinal);
        }

        // write file
        std::ofstream defFile;
        defFile.open(filename);
        if (defFile.is_open())
        {
            defFile << defStr;
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

bool GenerateProxyDll(PE& dll)
{
    std::vector<Export> exports = GetExports(dll);
    std::string dllName = std::string(dll.fileName).substr(0, strnlen(dll.fileName, MAX_LENGTH + 1) - 4);
    if (GenerateDef(exports, dllName) && GenerateCpp(exports, dllName, dll.is32Bits)) {
        if (!dll.is32Bits)
        {
            return GenerateAsm(exports, dllName);
        }
        return true;
    }
    return false;
}
