#pragma once

namespace dotnet
{
	namespace metadatatables
	{
		typedef struct IndexSizes
		{
			unsigned char strings;
			unsigned char guid;
			unsigned char blob;
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
		} IndexSizes;

		enum TablesEnum
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
			GenericParamConstraint = 44
		};

		// base class
		class BaseTable
		{
		public:
			DWORD numberOfRows = 0;
		};

		class Module : BaseTable {};
		class TypeRef : BaseTable {};
		class TypeDef : BaseTable {};
		class Field : BaseTable {};
		class MethodDef : BaseTable {};
		class Param : BaseTable {};
		class InterfaceImpl : BaseTable {};
		class MemberRef : BaseTable {};
		class Constant : BaseTable {};
		class CustomAttribute : BaseTable {};
		class FieldMarshal : BaseTable {};
		class DeclSecurity : BaseTable {};
		class ClassLayout : BaseTable {};
		class FieldLayout : BaseTable {};
		class StandAloneSig : BaseTable {};
		class EventMap : BaseTable {};
		class Event : BaseTable {};
		class PropertyMap : BaseTable {};
		class Property : BaseTable {};
		class MethodSemantics : BaseTable {};
		class MethodImpl : BaseTable {};
		class ModuleRef : BaseTable {};
		class TypeSpec : BaseTable {};
		class ImplMap : BaseTable {};
		class FieldRVA : BaseTable {};
		class Assembly : BaseTable {};
		class AssemblyProcessor : BaseTable {};
		class AssemblyOS : BaseTable {};
		class AssemblyRef : BaseTable {};
		class AssemblyRefProcessor : BaseTable {};
		class AssemblyRefOS : BaseTable {};
		class File : BaseTable {};
		class ExportedType : BaseTable {};
		class ManifestResource : BaseTable {};
		class NestedClass : BaseTable {};
		class GenericParam : BaseTable {};
		class GenericParamConstraint : BaseTable {};
	}
}