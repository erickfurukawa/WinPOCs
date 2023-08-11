#include <iostream>
#include <string>
#include <format>
#include "../Common/PE.h"

namespace
{
    std::string RemoveTrailingComma(std::string str)
    {
        std::string tmp = str.substr(0, str.size() - 2);
        tmp += "\n";
        return tmp;
    }
}

int main(int argc, char** argv)
{
    std::string filePath;
    if (argc == 2)
    {
        filePath = std::string(argv[1]);
    }
    else
    {
        std::cout << "File path:\n";
        std::cin >> filePath;
    }

    PE file = PE(filePath.c_str());
    if (!file.isDotNet)
    {
        std::cerr << "File is not .NET!";
        return 1;
    }

    std::string jsonStr = "";

    dotnet::Metadata metadata = file.dotnetMetadata;

    jsonStr += "{\n";

    // TypeRef table -------------------------
    jsonStr += "\t\"TypeRef\": [ \n";

    dotnet::metadatatables::TypeRef* typeRefTable = (dotnet::metadatatables::TypeRef*)metadata.metadataTablesStream.tables[dotnet::metadatatables::TablesEnum::TypeRef];
    for (dotnet::metadatatables::TypeRefEntry &entry : typeRefTable->entries)
    {
        std::string typeName = std::string((char*)metadata.stringsStream.address + entry.typeName);
        typeName = "\"" + typeName + "\"";
        std::string typeNamespace = std::string((char*)metadata.stringsStream.address + entry.typeNamespace);
        typeNamespace = "\"" + typeNamespace + "\"";

        jsonStr += "\t\t{\n";
        jsonStr += std::format("\t\t\t\"TypeName\": {},\n", typeName);
        jsonStr += std::format("\t\t\t\"TypeNamespace\": {}\n", typeNamespace);
        jsonStr += "\t\t},\n";
    }
    jsonStr = RemoveTrailingComma(jsonStr);
    jsonStr += "\t],\n\n";

    // ModuleRef table -------------------------
    jsonStr += "\t\"ModuleRef\": [ \n";

    dotnet::metadatatables::ModuleRef* moduleRefTable = (dotnet::metadatatables::ModuleRef*)metadata.metadataTablesStream.tables[dotnet::metadatatables::TablesEnum::ModuleRef];
    for (dotnet::metadatatables::ModuleRefEntry &entry : moduleRefTable->entries)
    {
        std::string name = std::string((char*)metadata.stringsStream.address + entry.name);
        name = "\"" + name + "\"";

        jsonStr += "\t\t{\n";
        jsonStr += std::format("\t\t\t\"Name\": {}\n", name);
        jsonStr += "\t\t},\n";
    }
    jsonStr = RemoveTrailingComma(jsonStr);
    jsonStr += "\t],\n\n";

    // AssemblyRef  table -------------------------
    jsonStr += "\t\"AssemblyRef\": [ \n";

    dotnet::metadatatables::AssemblyRef* assemblyRefTable= (dotnet::metadatatables::AssemblyRef*)metadata.metadataTablesStream.tables[dotnet::metadatatables::TablesEnum::AssemblyRef];
    for (dotnet::metadatatables::AssemblyRefEntry &entry : assemblyRefTable->entries)
    {
        std::string name = std::string((char*)metadata.stringsStream.address + entry.name);
        name = "\"" + name + "\"";

        jsonStr += "\t\t{\n";
        jsonStr += std::format("\t\t\t\"Name\": {}\n", name);
        jsonStr += "\t\t},\n";
    }
    jsonStr = RemoveTrailingComma(jsonStr);
    jsonStr += "\t]\n\n";

    jsonStr += "}\n";
    std::cout << jsonStr;

    return 0;
}