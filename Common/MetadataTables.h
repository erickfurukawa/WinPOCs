#pragma once

#include <Windows.h>
#include <vector>

namespace dotnet
{
	namespace metadatatables
	{
		namespace TablesEnum
		{
			enum
			{
				Module = 0,
				TypeRef = 1,
				TypeDef = 2,
				Field = 4,
				MethodDef = 6,
				Param = 8,
				InterfaceImpl = 9,
				MemberRef = 10,
				Constant = 11,
				CustomAttribute = 12,
				FieldMarshal = 13,
				DeclSecurity = 14,
				ClassLayout = 15,
				FieldLayout = 16,
				StandAloneSig = 17,
				EventMap = 18,
				Event = 20,
				PropertyMap = 21,
				Property = 23,
				MethodSemantics = 24,
				MethodImpl = 25,
				ModuleRef = 26,
				TypeSpec = 27,
				ImplMap = 28,
				FieldRVA = 29,
				Assembly = 32,
				AssemblyProcessor = 33,
				AssemblyOS = 34,
				AssemblyRef = 35,
				AssemblyRefProcessor = 36,
				AssemblyRefOS = 37,
				File = 38,
				ExportedType = 39,
				ManifestResource = 40,
				NestedClass = 41,
				GenericParam = 42,
				MethodSpec = 43,
				GenericParamConstraint = 44
			};
		}

		typedef struct IndexSizes
		{
			unsigned char string;
			unsigned char guid;
			unsigned char blob;
			unsigned char typeDef;
			unsigned char field;
			unsigned char methodDef;
			unsigned char param;
			unsigned char event; 
			unsigned char property;
			unsigned char moduleRef;
			unsigned char assemblyRef;
			unsigned char genericParam;

			// coded indexes
			unsigned char typeDefOrRef;
			unsigned char hasConstant;
			unsigned char hasCustomAttribute;
			unsigned char hasFieldMarshall;
			unsigned char hasDeclSecurity;
			unsigned char memberRefParent;
			unsigned char hasSemantics;
			unsigned char methodDefOrRef;
			unsigned char memberForwarded;
			unsigned char implementation;
			unsigned char customAttributeType;
			unsigned char resolutionScope;
			unsigned char typeOrMethodDef;
		} IndexSizes;

		// table entries ----------------------------------------------------------------
		typedef struct TypeRefEntry
		{
			DWORD resolutionScope;
			DWORD typeName;
			DWORD typeNamespace;
		} TypeRefEntry;

		typedef struct TypeDefEntry
		{
			DWORD flags;
			DWORD typeName;
			DWORD typeNamespace;
			DWORD extends;
			DWORD fieldList;
			DWORD methodList;
		} TypeDefEntry;

		typedef struct FieldEntry
		{
			WORD flags;
			DWORD name;
			DWORD signature;
		} FieldEntry;

		typedef struct MethodDefEntry
		{
			DWORD rva;
			WORD implFlags;
			WORD flags;
			DWORD name;
			DWORD signature;
			DWORD paramList;
		} MethodDefEntry;

		typedef struct ParamEntry
		{
			WORD flags;
			WORD sequence;
			DWORD name;
		} ParamEntry;

		typedef struct InterfaceImplEntry
		{
			DWORD classIndex;
			DWORD interfaceIndex;
		} InterfaceImplEntry;

		typedef struct MemberRefEntry
		{
			DWORD classIndex;
			DWORD name;
			DWORD signature;
		} MemberRefEntry;

		typedef struct ConstantEntry
		{
			WORD type;
			DWORD parent;
			DWORD value;
		} ConstantEntry;

		typedef struct CustomAttributeEntry
		{
			DWORD parent;
			DWORD type;
			DWORD value;
		} CustomAttributeEntry;

		typedef struct FieldMarshalEntry
		{
			DWORD parent;
			DWORD nativeType;
		} FieldMarshalEntry;

		typedef struct DeclSecurityEntry
		{
			WORD action;
			DWORD parent;
			DWORD permissionSet;
		} DeclSecurityEntry;

		typedef struct ClassLayoutEntry
		{
			WORD packingSize;
			DWORD classSize;
			DWORD parent;
		} ClassLayoutEntry;

		typedef struct FieldLayoutEntry
		{
			DWORD offset;
			DWORD field;
		} FieldLayoutEntry;

		typedef struct StandAloneSigEntry
		{
			DWORD signature;
		} StandAloneSigEntry;

		typedef struct EventMapEntry
		{
			DWORD parent;
			DWORD eventList;
		} EventMapEntry;

		typedef struct EventEntry
		{
			WORD eventFlags;
			DWORD name;
			DWORD eventType;
		} EventEntry;

		typedef struct PropertyMapEntry
		{
			DWORD parent;
			DWORD propertyList;
		} PropertyMapEntry;

		typedef struct PropertyEntry
		{
			WORD flags;
			DWORD name;
			DWORD type;
		} PropertyEntry;

		typedef struct MethodSemanticsEntry
		{
			WORD semantics;
			DWORD method;
			DWORD association;
		} MethodSemanticsEntry;

		typedef struct MethodImplEntry
		{
			DWORD classIndex;
			DWORD methodBody;
			DWORD methodDeclaration;
		} MethodImplEntry;

		typedef struct ModuleRefEntry
		{
			DWORD name;
		} ModuleRefEntry;

		typedef struct TypeSpecEntry
		{
			DWORD signature;
		} TypeSpecEntry;

		typedef struct ImplMapEntry
		{
			WORD mappingFlags;
			DWORD memberForwarded;
			DWORD importName;
			DWORD importScope;
		} ImplMapEntry;

		typedef struct FieldRVAEntry
		{
			DWORD rva;
			DWORD field;
		} FieldRVAEntry;

		typedef struct AssemblyEntry
		{
			DWORD hashAlgId;
			WORD majorVersion;
			WORD minorVersion;
			WORD buildNumber;
			WORD revisionNumber;
			DWORD flags;
			DWORD publicKey;
			DWORD name;
			DWORD culture;
		} AssemblyEntry;

		typedef struct AssemblyProcessorEntry
		{
			DWORD processor;
		} AssemblyProcessorEntry;

		typedef struct AssemblyOSEntry
		{
			DWORD OSPlatformID;
			DWORD OSMajorVersion;
			DWORD OSMinorVersion;
		} AssemblyOSEntry;

		typedef struct AssemblyRefEntry
		{
			WORD majorVersion;
			WORD minorVersion;
			WORD buildNumber;
			WORD revisionNumber;
			DWORD flags;
			DWORD publicKeyOrToken;
			DWORD name;
			DWORD culture;
			DWORD hashValue;

		} AssemblyRefEntry;

		typedef struct AssemblyRefProcessorEntry
		{
			DWORD processor;
			DWORD assemblyRef;
		} AssemblyRefProcessorEntry;

		typedef struct AssemblyRefOSEntry
		{
			DWORD OSPlatformId;
			DWORD OSMajorVersion;
			DWORD OSMinorVersion;
			DWORD assemblyRef;
		} AssemblyRefOSEntry;

		typedef struct FileEntry
		{
			DWORD flags;
			DWORD name;
			DWORD hashValue;
		} FileEntry;

		typedef struct ExportedTypeEntry
		{
			DWORD flags;
			DWORD typeDefId;
			DWORD typeName;
			DWORD typeNamespace;
			DWORD implementation;
		} ExportedTypeEntry;

		typedef struct ManifestResourceEntry
		{
			DWORD offset;
			DWORD flags;
			DWORD name;
			DWORD implementation;
		} ManifestResourceEntry;

		typedef struct NestedClassEntry
		{
			DWORD nestedClass;
			DWORD enclosingClass;
		} NestedClassEntry;

		typedef struct GenericParamEntry
		{
			WORD number;
			WORD flags;
			DWORD owner;
			DWORD name;
		} GenericParamEntry;

		typedef struct MethodSpecEntry
		{
			DWORD method;
			DWORD instantiation;
		} MethodSpecEntry;

		typedef struct GenericParamConstraintEntry
		{
			DWORD owner;
			DWORD constraint;
		} GenericParamConstraintEntry;

		// metadata tables ----------------------------------------------------------------
		// base class 
		class BaseTable
		{
		public:
			DWORD numberOfRows = 0;
			virtual void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class Module : public BaseTable
		{
		public:
			WORD generation; // reserved, 0
			DWORD name; // String heap index
			DWORD mvid; // GUID heap index
			DWORD encId; // GUID heap index, 0
			DWORD encBaseId; // GUID heap index, 0

			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class TypeRef : public BaseTable
		{
		public:
			std::vector<TypeRefEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class TypeDef : public BaseTable
		{
		public:
			std::vector<TypeDefEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class Field : public BaseTable
		{
		public:
			std::vector<FieldEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class MethodDef : public BaseTable
		{
		public:
			std::vector<MethodDefEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class Param : public BaseTable
		{
		public:
			std::vector<ParamEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class InterfaceImpl : public BaseTable
		{
		public:
			std::vector<InterfaceImplEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class MemberRef : public BaseTable
		{
		public:
			std::vector<MemberRefEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class Constant : public BaseTable
		{
		public:
			std::vector<ConstantEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class CustomAttribute : public BaseTable
		{
		public:
			std::vector<CustomAttributeEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class FieldMarshal : public BaseTable
		{
		public:
			std::vector<FieldMarshalEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class DeclSecurity : public BaseTable
		{
		public:
			std::vector<DeclSecurityEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class ClassLayout : public BaseTable
		{
		public:
			std::vector<ClassLayoutEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class FieldLayout : public BaseTable {
		public:
			std::vector<FieldLayoutEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class StandAloneSig : public BaseTable
		{
		public:
			std::vector<StandAloneSigEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class EventMap : public BaseTable
		{
		public:
			std::vector<EventMapEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class Event : public BaseTable
		{
		public:
			std::vector<EventEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class PropertyMap : public BaseTable
		{
		public:
			std::vector<PropertyMapEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class Property : public BaseTable
		{
		public:
			std::vector<PropertyEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class MethodSemantics : public BaseTable
		{
		public:
			std::vector<MethodSemanticsEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class MethodImpl : public BaseTable
		{
		public:
			std::vector<MethodImplEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class ModuleRef : public BaseTable
		{
		public:
			std::vector<ModuleRefEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class TypeSpec : public BaseTable
		{
		public:
			std::vector<TypeSpecEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class ImplMap : public BaseTable
		{
		public:
			std::vector<ImplMapEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class FieldRVA : public BaseTable
		{
		public:
			std::vector<FieldRVAEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class Assembly : public BaseTable
		{
		public:
			std::vector<AssemblyEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class AssemblyProcessor : public BaseTable
		{
		public:
			std::vector<AssemblyProcessorEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class AssemblyOS : public BaseTable
		{
		public:
			std::vector<AssemblyOSEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class AssemblyRef : public BaseTable
		{
		public:
			std::vector<AssemblyRefEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class AssemblyRefProcessor : public BaseTable
		{
		public:
			std::vector<AssemblyRefProcessorEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class AssemblyRefOS : public BaseTable
		{
		public:
			std::vector<AssemblyRefOSEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class File : public BaseTable
		{
		public:
			std::vector<FileEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class ExportedType : public BaseTable
		{
		public:
			std::vector<ExportedTypeEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class ManifestResource : public BaseTable
		{
		public:
			std::vector<ManifestResourceEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class NestedClass : public BaseTable
		{
		public:
			std::vector<NestedClassEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class GenericParam : public BaseTable
		{
		public:
			std::vector<GenericParamEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class MethodSpec : public BaseTable
		{
		public:
			std::vector<MethodSpecEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		class GenericParamConstraint : public BaseTable
		{
		public:
			std::vector<GenericParamConstraintEntry> entries;
			void ReadData(BYTE** pTableAddress, IndexSizes sizes);
		};

		IndexSizes GetIndexSizes(DWORD tableRows[64], BYTE heapOffsetSizes);
	}
}