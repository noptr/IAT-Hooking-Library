#pragma once
#include <Windows.h>
#include <iostream>

namespace iat_hooker {

	namespace utility {

		auto str(const char* str1, const char* str2) {
			while (*str1 && *str2) {
				if (*str1 < *str2)
					return -1;
				if (*str1 > *str2)
					return 1;
				++str1; ++str2;
			}
			return *str1 ? -1 : *str2 ? 1 : 0;
		}

		void* get_export(std::string module, LPCSTR api)
		{
			auto base = (DWORD)GetModuleHandleA(module.c_str());
			if (!base)
				return 0;
			auto pDOS = (PIMAGE_DOS_HEADER)base;
			if (pDOS->e_magic != IMAGE_DOS_SIGNATURE)
				return 0;
			auto pNT = (PIMAGE_NT_HEADERS)(base + (DWORD)pDOS->e_lfanew);
			if (pNT->Signature != IMAGE_NT_SIGNATURE)
				return 0;
			auto pExport = (PIMAGE_EXPORT_DIRECTORY)(base + pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if (!pExport)
				return 0;
			auto names = (PDWORD)(base + pExport->AddressOfNames);
			auto ordinals = (PWORD)(base + pExport->AddressOfNameOrdinals);
			auto functions = (PDWORD)(base + pExport->AddressOfFunctions);
			for (auto i = 0; i < pExport->NumberOfFunctions; ++i) {
				LPCSTR name = (LPCSTR)(base + names[i]);
				if (!str(name, api))
					return (void*)(base + functions[ordinals[i]]);
			}
		}

	}

	void SetHook(unsigned char* func, unsigned char* dst)
	{
		char original_bytes[16];
		DWORD old_protection;
		VirtualProtect(func, 1024, PAGE_EXECUTE_READWRITE, &old_protection);
		memcpy(original_bytes, dst, sizeof(void*) == 4 ? 5 : 14);
		*func = 0xE9; 
		*(uint32_t*)(func + 1) = dst - func - 5;

		if (!VirtualProtect(func, 1024, old_protection, &old_protection))
		{
			memcpy(func, original_bytes, sizeof(void*) == 4 ? 5 : 14);
			return;
		}
	}

	void SetExportHook(std::string modName, std::string exportFunc, void* hookDest)
	{
		void* exported = (void*)utility::get_export(modName, exportFunc.c_str());
		SetHook((unsigned char*)exported, (unsigned char*)hookDest);
	}


}