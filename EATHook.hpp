#pragma once

#include <map>

namespace HwbpDetail
{
#if defined(HWBP_X64)
	static constexpr auto JMP_LEN = 14;	
#else
	static constexpr auto JMP_LEN = 5;
#endif
	inline std::map<void*, std::vector<uint8_t>> HookMap;
}


//! Grab export address and JMP hook it directly 
static void* HookExportDirect(
	std::string_view image_name, 
	std::string_view proc_name, 
	void* pHook,
	void** pfnOriginal)
{
	std::uintptr_t pImg = (std::uintptr_t)GetModuleHandleA(image_name.data());
	if (pImg == 0)
		return nullptr;

	IMAGE_DOS_HEADER* pDosHdr = 
		(IMAGE_DOS_HEADER*)pImg;
	IMAGE_NT_HEADERS* pPeHdr = 
		(IMAGE_NT_HEADERS*)(pImg + pDosHdr->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* pExpDir = 
		(IMAGE_EXPORT_DIRECTORY*)(pImg + pPeHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	std::uint32_t* pNameTable = (std::uint32_t*)(pImg + pExpDir->AddressOfNames);
	std::uint16_t* pOrdinalTable = (std::uint16_t*)(pImg + pExpDir->AddressOfNameOrdinals);
	std::uint32_t* pAddressTable = (std::uint32_t*)(pImg + pExpDir->AddressOfFunctions);
	DWORD prot{};

	for (int i = 0; i < pExpDir->NumberOfNames; i++)
	{
		const char* szExport = (const char*)(pImg + pNameTable[i]);

		if (proc_name.compare(szExport) == 0)
		{
			//
			// We can't hook by setting the RVA because ntdll!Kernel32ThreadInitThunkFunction 
			// will already have a value (it is set when the process is initialized)
			// This function needs a revisit, it's poorly coded and not safe in the slightest
			//
			hde_t hde{};
			std::size_t total_len{ 0 }, in_len{ 0 }, tmp_len{ 0 };
			uint8_t buffer[0x20]{};
			uint8_t hook_buffer[HwbpDetail::JMP_LEN]{};

			void* pAddress = (void*)(pImg + pAddressTable[pOrdinalTable[i]]);
			std::uint8_t* pTmp = (std::uint8_t*)pAddress;

			do
			{
				in_len = hde_disasm(pTmp, &hde);
				memcpy(&buffer[total_len], pTmp, in_len);
				total_len += in_len;
				pTmp += in_len;
			} while (total_len < HwbpDetail::JMP_LEN);

			//
			// Add to the hook map
			HwbpDetail::HookMap[pAddress] = std::vector<uint8_t>(total_len);
			memcpy(&HwbpDetail::HookMap[pAddress][0], pAddress, total_len);


			//
			// Assemble trampoline
			void* pTramp = VirtualAlloc(nullptr, sizeof buffer, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!pTramp)
				return nullptr;
				
			//
			// Call our hook
#if defined(HWBP_X64)
			buffer[total_len] = 0x49; // (rely on register r10..)
			buffer[total_len+1] = 0xba;
			*(std::uintptr_t*)(&buffer[total_len+2]) = (std::uintptr_t)pAddress + HwbpDetail::JMP_LEN;
			buffer[total_len + 10] = 0x41;
			buffer[total_len + 11] = 0xff;
			buffer[total_len + 12] = 0xe2;
#else
			buffer[total_len] = 0xe9;
			*(std::uint32_t*)(&buffer[total_len + 1]) =
				(((std::uintptr_t)pAddress + 5) - ((std::uintptr_t)pTramp + total_len + 5));
#endif

			memcpy(pTramp, buffer, sizeof(buffer));

			// 
			// Assemble a jmp to trampoline
#if defined(HWBP_X64)
			hook_buffer[0] = 0x49; // (rely on register r10..)
			hook_buffer[1] = 0xba;
			*(std::uintptr_t*)(&hook_buffer[2]) = (std::uintptr_t)pHook;
			hook_buffer[10] = 0x41;
			hook_buffer[11] = 0xff;
			hook_buffer[12] = 0xe2;
#else
			hook_buffer[0] = 0xe9;
			*(std::uint32_t*)(&hook_buffer[1]) = ((std::uintptr_t)pHook - ((std::uintptr_t)pAddress + 5));
#endif
			if (!VirtualProtect(pAddress, sizeof(hook_buffer), PAGE_EXECUTE_READWRITE, &prot))
			{
				VirtualFree(pTramp, 0, MEM_RELEASE);
				return nullptr;
			}

			memcpy(pAddress, hook_buffer, sizeof(hook_buffer));
			VirtualProtect(pAddress, sizeof(hook_buffer), prot, &prot);

			if (pfnOriginal)
				*pfnOriginal = pTramp;

			return pTramp;
		}
	}

	return nullptr;
}

static void UnHookExportDirect(
	std::string_view image_name,
	std::string_view proc_name)
{
	std::uintptr_t pImg = (std::uintptr_t)GetModuleHandleA(image_name.data());
	if (pImg == 0)
		return;

	IMAGE_DOS_HEADER* pDosHdr =
		(IMAGE_DOS_HEADER*)pImg;
	IMAGE_NT_HEADERS* pPeHdr =
		(IMAGE_NT_HEADERS*)(pImg + pDosHdr->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* pExpDir =
		(IMAGE_EXPORT_DIRECTORY*)(pImg + pPeHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	std::uint32_t* pNameTable = (std::uint32_t*)(pImg + pExpDir->AddressOfNames);
	std::uint16_t* pOrdinalTable = (std::uint16_t*)(pImg + pExpDir->AddressOfNameOrdinals);
	std::uint32_t* pAddressTable = (std::uint32_t*)(pImg + pExpDir->AddressOfFunctions);
	DWORD prot{};

	for (int i = 0; i < pExpDir->NumberOfNames; i++)
	{
		const char* szExport = (const char*)(pImg + pNameTable[i]);

		if (proc_name.compare(szExport) == 0)
		{
			void* pAddress = (void*)(pImg + pAddressTable[pOrdinalTable[i]]);
			auto it = HwbpDetail::HookMap.find(pAddress);

			if (it != HwbpDetail::HookMap.end())
			{
				if (!VirtualProtect(pAddress, it->second.size(), PAGE_EXECUTE_READWRITE, &prot))
				{
					return;
				}

				memcpy(pAddress, it->second.data(), it->second.size());
				VirtualProtect(pAddress, it->second.size(), prot, &prot);

				HwbpDetail::HookMap.erase(it);
			}
		}
	}
}