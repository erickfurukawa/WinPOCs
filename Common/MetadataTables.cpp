#include "MetadataTables.h"

namespace
{
	// given a mask of tables that an index indexes, returns the size required (WORD or DWORD) for that index
	unsigned char GetIndexSize(DWORD tableRows[64], unsigned long long mask, int minNumberOfTags = 0)
	{
		int numberOfTags = 0;
		for (int i = 0; i < 64; i++)
		{
			if ((1ull << i) & mask)
			{
				numberOfTags++;
			}
		}
		if (numberOfTags < minNumberOfTags)
		{
			numberOfTags = minNumberOfTags;
		}

		int tagSize = 0;
		for (tagSize = 0; ; tagSize++)
		{
			if ((1 << tagSize) >= numberOfTags)
			{
				break;
			}
		}

		DWORD maxRows = 0;
		for (int i = 0; i < 64; i++)
		{
			if ((1ull << i) & mask)
			{
				if (tableRows[i] > maxRows)
				{
					maxRows = tableRows[i];
				}
			}
		}

		unsigned int maxIndex = 1 << (sizeof(WORD) * 8 - tagSize);
		if (maxIndex < maxRows)
			return 4;
		return 2;
	}

	DWORD ReadIndex(BYTE** pAddress, unsigned char size)
	{
		DWORD value;
		if (size == 2)
		{
			value = *reinterpret_cast<WORD*>(*pAddress);
		}
		else
		{
			value = *reinterpret_cast<DWORD*>(*pAddress);
		}
		*pAddress += size;
		return value;
	}
}

namespace dotnet
{
	namespace metadatatables
	{
		IndexSizes GetIndexSizes(DWORD tableRows[64], BYTE heapOffsetSizes)
		{
			IndexSizes sizes;

			sizes.string = heapOffsetSizes & 1 ? 4 : 2;
			sizes.guid = heapOffsetSizes & 2 ? 4 : 2;
			sizes.blob = heapOffsetSizes & 4 ? 4 : 2;

			sizes.typeDef = tableRows[TablesEnum::TypeDef] > 0xFFFF ? 4 : 2;
			sizes.field = tableRows[TablesEnum::Field] > 0xFFFF ? 4 : 2;
			sizes.methodDef = tableRows[TablesEnum::MethodDef] > 0xFFFF ? 4 : 2;
			sizes.param = tableRows[TablesEnum::Param] > 0xFFFF ? 4 : 2;

			unsigned long long typeDefOrRefMask = 0;
			typeDefOrRefMask |= 1ull << TablesEnum::TypeDef;
			typeDefOrRefMask |= 1ull << TablesEnum::TypeRef;
			typeDefOrRefMask |= 1ull << TablesEnum::TypeSpec;
			sizes.typeDefOrRef = GetIndexSize(tableRows, typeDefOrRefMask);

			unsigned long long hasConstantMask = 0;
			hasConstantMask |= 1ull << TablesEnum::Field;
			hasConstantMask |= 1ull << TablesEnum::Param;
			hasConstantMask |= 1ull << TablesEnum::Property;
			sizes.hasConstant = GetIndexSize(tableRows, hasConstantMask);

			unsigned long long hasCustomAttributeMask = 0;
			hasCustomAttributeMask |= 1ull << TablesEnum::MethodDef;
			hasCustomAttributeMask |= 1ull << TablesEnum::Field;
			hasCustomAttributeMask |= 1ull << TablesEnum::TypeRef;
			hasCustomAttributeMask |= 1ull << TablesEnum::TypeDef;
			hasCustomAttributeMask |= 1ull << TablesEnum::Param;
			hasCustomAttributeMask |= 1ull << TablesEnum::InterfaceImpl;
			hasCustomAttributeMask |= 1ull << TablesEnum::MemberRef;
			hasCustomAttributeMask |= 1ull << TablesEnum::Module;
			// hasCustomAttributeMask |= 1 << TablesEnum::Permission; TODO: blob heap index???
			hasCustomAttributeMask |= 1ull << TablesEnum::Property;
			hasCustomAttributeMask |= 1ull << TablesEnum::Event;
			hasCustomAttributeMask |= 1ull << TablesEnum::StandAloneSig;
			hasCustomAttributeMask |= 1ull << TablesEnum::ModuleRef;
			hasCustomAttributeMask |= 1ull << TablesEnum::TypeSpec;
			hasCustomAttributeMask |= 1ull << TablesEnum::Assembly;
			hasCustomAttributeMask |= 1ull << TablesEnum::AssemblyRef;
			hasCustomAttributeMask |= 1ull << TablesEnum::File;
			hasCustomAttributeMask |= 1ull << TablesEnum::ExportedType;
			hasCustomAttributeMask |= 1ull << TablesEnum::ManifestResource;
			sizes.hasCustomAttribute = GetIndexSize(tableRows, hasCustomAttributeMask);

			unsigned long long hasFieldMarshallMask = 0;
			hasFieldMarshallMask |= 1ull << TablesEnum::Field;
			hasFieldMarshallMask |= 1ull << TablesEnum::Param;
			sizes.hasFieldMarshall = GetIndexSize(tableRows, hasFieldMarshallMask);

			unsigned long long hasDeclSecurityMask = 0;
			hasDeclSecurityMask |= 1ull << TablesEnum::TypeDef;
			hasDeclSecurityMask |= 1ull << TablesEnum::MethodDef;
			hasDeclSecurityMask |= 1ull << TablesEnum::Assembly;
			sizes.hasDeclSecurity = GetIndexSize(tableRows, hasDeclSecurityMask);

			unsigned long long memberRefParentMask = 0;
			memberRefParentMask |= 1ull << TablesEnum::TypeDef;
			memberRefParentMask |= 1ull << TablesEnum::TypeRef;
			memberRefParentMask |= 1ull << TablesEnum::ModuleRef;
			memberRefParentMask |= 1ull << TablesEnum::MethodDef;
			memberRefParentMask |= 1ull << TablesEnum::TypeSpec;
			sizes.memberRefParent = GetIndexSize(tableRows, memberRefParentMask);

			unsigned long long hasSemanticsMask = 0;
			hasSemanticsMask |= 1ull << TablesEnum::Event;
			hasSemanticsMask |= 1ull << TablesEnum::Property;
			sizes.hasSemantics = GetIndexSize(tableRows, hasSemanticsMask);

			unsigned long long methodDefOrRefMask = 0;
			methodDefOrRefMask |= 1ull << TablesEnum::MethodDef;
			methodDefOrRefMask |= 1ull << TablesEnum::MemberRef;
			sizes.methodDefOrRef = GetIndexSize(tableRows, methodDefOrRefMask);

			unsigned long long memberForwardedMask = 0;
			memberForwardedMask |= 1ull << TablesEnum::Field;
			memberForwardedMask |= 1ull << TablesEnum::MethodDef;
			sizes.memberForwarded = GetIndexSize(tableRows, memberForwardedMask);

			unsigned long long implementationMask = 0;
			implementationMask |= 1ull << TablesEnum::File;
			implementationMask |= 1ull << TablesEnum::AssemblyRef;
			implementationMask |= 1ull << TablesEnum::ExportedType;
			sizes.implementation = GetIndexSize(tableRows, implementationMask);

			// customAttributeType has a few tag values that are not used
			unsigned long long customAttributeTypeMask = 0;
			customAttributeTypeMask |= 1ull << TablesEnum::MethodDef;
			customAttributeTypeMask |= 1ull << TablesEnum::MemberRef;
			sizes.customAttributeType = GetIndexSize(tableRows, customAttributeTypeMask, 5);

			unsigned long long resolutionScopeMask = 0;
			resolutionScopeMask |= 1ull << TablesEnum::Module;
			resolutionScopeMask |= 1ull << TablesEnum::ModuleRef;
			resolutionScopeMask |= 1ull << TablesEnum::AssemblyRef;
			resolutionScopeMask |= 1ull << TablesEnum::TypeRef;
			sizes.resolutionScope = GetIndexSize(tableRows, resolutionScopeMask);

			return sizes;
		}

		void BaseTable::ReadData(BYTE** pTableAddress, IndexSizes sizes)
		{
			return;
		}

		void Module::ReadData(BYTE** pTableAddress, IndexSizes sizes)
		{
			this->generation = *reinterpret_cast<WORD*>(*pTableAddress);
			*pTableAddress += sizeof(WORD);

			this->name = ReadIndex(pTableAddress, sizes.string);
			this->mvid = ReadIndex(pTableAddress, sizes.guid);
			this->encId = ReadIndex(pTableAddress, sizes.guid);
			this->encBaseId = ReadIndex(pTableAddress, sizes.guid);
		}

		void TypeRef::ReadData(BYTE** pTableAddress, IndexSizes sizes)
		{
			for (unsigned int i = 0; i < this->numberOfRows; i++)
			{
				TypeRefEntry entry = {};
				entry.resolutionScope = ReadIndex(pTableAddress, sizes.resolutionScope);
				entry.typeName = ReadIndex(pTableAddress, sizes.string);
				entry.typeNamespace = ReadIndex(pTableAddress, sizes.string);

				this->entries.push_back(entry);
			}
		}

		void TypeDef::ReadData(BYTE** pTableAddress, IndexSizes sizes)
		{
			for (unsigned int i = 0; i < this->numberOfRows; i++)
			{
				TypeDefEntry entry = {};
				entry.flags = ReadIndex(pTableAddress, sizeof(DWORD));
				entry.typeName = ReadIndex(pTableAddress, sizes.string);
				entry.typeNamespace = ReadIndex(pTableAddress, sizes.string);
				entry.extends = ReadIndex(pTableAddress, sizes.typeDefOrRef);
				entry.fieldList = ReadIndex(pTableAddress, sizes.field);
				entry.methodList = ReadIndex(pTableAddress, sizes.methodDef);

				this->entries.push_back(entry);
			}
		}

		void Field::ReadData(BYTE** pTableAddress, IndexSizes sizes)
		{
			for (unsigned int i = 0; i < this->numberOfRows; i++)
			{
				FieldEntry entry = {};
				entry.flags = static_cast<WORD>(ReadIndex(pTableAddress, sizeof(WORD)));
				entry.name = ReadIndex(pTableAddress, sizes.string);
				entry.signature = ReadIndex(pTableAddress, sizes.blob);

				this->entries.push_back(entry);
			}
		}

		void MethodDef::ReadData(BYTE** pTableAddress, IndexSizes sizes)
		{
			for (unsigned int i = 0; i < this->numberOfRows; i++)
			{
				MethodDefEntry entry = {};
				entry.rva = ReadIndex(pTableAddress, sizeof(DWORD));
				entry.implFlags = static_cast<WORD>(ReadIndex(pTableAddress, sizeof(WORD)));
				entry.flags = static_cast<WORD>(ReadIndex(pTableAddress, sizeof(WORD)));
				entry.name = ReadIndex(pTableAddress, sizes.string);
				entry.signature = ReadIndex(pTableAddress, sizes.blob);
				entry.paramList = ReadIndex(pTableAddress, sizes.param);

				this->entries.push_back(entry);
			}
		}

		void Param::ReadData(BYTE** pTableAddress, IndexSizes sizes)
		{
			for (unsigned int i = 0; i < this->numberOfRows; i++)
			{
				ParamEntry entry = {};
				entry.flags = static_cast<WORD>(ReadIndex(pTableAddress, sizeof(WORD)));
				entry.sequence = static_cast<WORD>(ReadIndex(pTableAddress, sizeof(WORD)));
				entry.name = ReadIndex(pTableAddress, sizes.string);

				this->entries.push_back(entry);
			}
		}

		void InterfaceImpl::ReadData(BYTE** pTableAddress, IndexSizes sizes)
		{
			for (unsigned int i = 0; i < this->numberOfRows; i++)
			{
				InterfaceImplEntry entry = {};
				entry.classIndex = ReadIndex(pTableAddress, sizes.typeDef);
				entry.interfaceIndex = ReadIndex(pTableAddress, sizes.typeDefOrRef);

				this->entries.push_back(entry);
			}
		}

		void MemberRef::ReadData(BYTE** pTableAddress, IndexSizes sizes)
		{
			for (unsigned int i = 0; i < this->numberOfRows; i++)
			{
				MemberRefEntry entry = {};
				entry.classIndex = ReadIndex(pTableAddress, sizes.memberRefParent);
				entry.name = ReadIndex(pTableAddress, sizes.string);
				entry.signature = ReadIndex(pTableAddress, sizes.blob);

				this->entries.push_back(entry);
			}
		}

		void Constant::ReadData(BYTE** pTableAddress, IndexSizes sizes)
		{
			for (unsigned int i = 0; i < this->numberOfRows; i++)
			{
				ConstantEntry entry = {};
				entry.type = static_cast<WORD>(ReadIndex(pTableAddress, sizeof(WORD)));
				entry.parent = ReadIndex(pTableAddress, sizes.hasConstant);
				entry.value = ReadIndex(pTableAddress, sizes.blob);

				this->entries.push_back(entry);
			}
		}
	}
}