#include "HardwareBreakpoint.hpp"

static std::vector<HardwareBreakpoint*> s_hwbpList;
static bool s_addedHandler{ false };

static LONG WINAPI HwbpVectoredExceptionHandler(EXCEPTION_POINTERS* pException);

//
// We need to hook thread creations and modify them
void(__fastcall* _HwbpBaseThreadInitThunk)(ULONG, LPTHREAD_START_ROUTINE, LPVOID);
static void __fastcall HwbpBaseThreadInitThunk(ULONG ulState, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam);

#if defined(HWBP_X64)
static constexpr std::uint8_t _JmpOut[] = { 0x48, 0xB8, 0x0D, 0xD0, 0x0D, 0x60, 0x15, 0xEE, 0xFF, 0xC0, 0xFF, 0xE0 };
static constexpr auto _JmpOutOffset = 0x2;
#define SET_INSTRUCTION_PTR(i, p) i->ContextRecord->Rip = (std::uintptr_t)p
#else
static constexpr std::uint8_t _JmpOut[] = { 0x68, 0xEF, 0xBE, 0xAD, 0xDE, 0xC3 };
static constexpr auto _JmpOutOffset = 0x1;
#define SET_INSTRUCTION_PTR(i, p) i->ContextRecord->Eip = (std::uintptr_t)p
#endif

HardwareBreakpoint::HardwareBreakpoint(bool singleThread, bool runOnce)
	: m_singleThread(singleThread)
	, m_runOnce(runOnce)
{
	if (!s_addedHandler)
	{
		//
		// Add a VEH
		AddVectoredExceptionHandler(0, HwbpVectoredExceptionHandler);
		//
		// Hook BaseThreadInitThunk
		if (!HookExportDirect("kernel32", "BaseThreadInitThunk", HwbpBaseThreadInitThunk, (void**)&_HwbpBaseThreadInitThunk))
			FormatError("[!] Error hooking BaseThreadInitThunk\n");

		s_addedHandler = true;
	}
	

	s_hwbpList.push_back(this);
}

HardwareBreakpoint::~HardwareBreakpoint()
{
	Disable();

	auto it = std::find(s_hwbpList.begin(), s_hwbpList.end(), this);

	if (it != s_hwbpList.end())
		s_hwbpList.erase(it);
}

bool HardwareBreakpoint::Create(void* address, BreakpointLength size, BreakpointCondition cond, std::optional<BreakpointHandler> handler) noexcept
{
	if (m_regIdx != -1)
		return false;

	m_address = (std::uintptr_t)address;
	m_size = size;
	m_cond = cond;

	if (handler.has_value())
	{
		m_handler = handler.value();
	
		//
		// Invalid handler mixture, reset it
		if (m_handler.m_type == BreakpointHandlerType::Hook && cond != BreakpointCondition::Execute)
		{
			m_handler.m_type = BreakpointHandlerType::None;
			FormatError("[!] Invalid BreakpointHandlerType (wanted hook in a R/RW breakpoint)\n");
		}
	}


	if (m_cond == BreakpointCondition::Execute)
	{
		//
		// Force one byte length
		m_size = BreakpointLength::OneByte;

		//
		// Calculate entire instruction len
		hde_t hde{};
		unsigned int inlen = hde_disasm(address, &hde);
		
		//
		// If it is a jmp/call, let's go to the destination
		switch (hde.opcode)
		{
		case 0xe8:
		case 0xe9:
			m_address += hde.imm.imm32 + inlen;
			inlen = hde_disasm((void*)m_address, &hde);
			break;
		}

		//
		// New jmp address
		std::uintptr_t newOffset = m_address + inlen;

		m_buffer.setup(inlen + sizeof(_JmpOut), PAGE_EXECUTE_READWRITE);
		m_buffer.copy(0, (void*)m_address, inlen);
		m_buffer.copy(inlen, &_JmpOut[0], sizeof(_JmpOut));
		m_buffer.copy(inlen + _JmpOutOffset, &newOffset, sizeof(newOffset));
	}


	//
	// Setup a context for GetThreadContext
	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;


	if (m_singleThread)
	{
		HANDLE hThisThread = GetCurrentThread();
		
		if (!GetThreadContext(hThisThread, &ctx))
		{
			FormatError("[!] Error calling GetThreadContext (err: {})\n", GetLastError());
			return false;
		}

		if (!ModifyThreadContext(&ctx))
		{
			FormatError("[!] Error calling ModifyThreadContext\n");
			return false;
		}

		//
		// Set the new thread context
		SetThreadContext(hThisThread, &ctx);
	}
	else
	{
		//
		// Iterator over all threads in the process
		ForEachThread(
			[this, &ctx](HANDLE hThread)
			{
				if (!GetThreadContext(hThread, &ctx))
				{
					FormatError("[!] Error calling GetThreadContext (err: {})\n", GetLastError());
					return;
				}

				if (!ModifyThreadContext(&ctx))
				{
					FormatError("[!] Error calling ModifyThreadContext\n");
					return;
				}

				//
				// Set the new thread context
				SetThreadContext(hThread, &ctx);
			});
	}
}


void HardwareBreakpoint::Disable() noexcept
{
	if (m_regIdx == -1)
		return;

	m_disabled = true;

	//
	// Setup a context for GetThreadContext
	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	//
	// Clear out the debug registers
	switch (m_regIdx)
	{
	case 0:
		ctx.Dr0 = 0;
		break;
	case 1:
		ctx.Dr1 = 0;
		break;
	case 2:
		ctx.Dr2 = 0;
		break;
	case 3:
		ctx.Dr3 = 0;
		break;
	}

	TBitSet<std::uintptr_t> dr7{ ctx.Dr7 };

	//
	// Set this slot as disabled
	dr7.SetBit(m_regIdx * 2, false);
	//
	// Clear the condition type of the breakpoint (16-17, 21-20, 24-25, 28-29)
	dr7.SetBits(16 + (m_regIdx * 2), 0);
	//
	// Clear the size of the breakpoint (18-19, 22-23, 26-27, 30-31)
	dr7.SetBit(18 + (m_regIdx * 2), 0);

	if (m_singleThread)
	{
		HANDLE hThisThread = GetCurrentThread();

		if (!GetThreadContext(hThisThread, &ctx))
		{
			FormatError("[!] Error calling GetThreadContext (err: {})\n", GetLastError());
			return;
		}

		ctx.Dr7 = static_cast<decltype(CONTEXT::Dr7)>(dr7.ToValue());

		// Set the new thread context
		if (!SetThreadContext(hThisThread, &ctx))
		{
			FormatError("[!] Error calling SetThreadContext (err: {})\n", GetLastError());
		}
	}
	else
	{
		//
		// Iterator over all threads in the process
		ForEachThread(
			[this, &ctx, dr7](HANDLE hThread)
			{
				if (!GetThreadContext(hThread, &ctx))
				{
					FormatError("[!] Error calling GetThreadContext (err: {})\n", GetLastError());
					return;
				}

				ctx.Dr7 = static_cast<decltype(CONTEXT::Dr7)>(dr7.ToValue());

				//
				// Set the new thread context
				if (!SetThreadContext(hThread, &ctx))
				{
					FormatError("[!] Error calling SetThreadContext (err: {})\n", GetLastError());
				}
			});
	}
}

bool HardwareBreakpoint::ModifyThreadContext(CONTEXT* ctx) noexcept
{
	TBitSet<std::uintptr_t> dr7 {ctx->Dr7};

	//
	// Try to find a free debug register

	if (m_regIdx == -1)
	{
		for (int i = 0; i < 4; i++)
		{
			if (!dr7.IsBitSet(i * 2))
			{
				FormatMsg("[+] Found free index at {}\n", i);
				m_regIdx = i;
				break;
			}
		}
	}

	//
	// They're all apparently taken.
	if (m_regIdx == -1)
	{
		FormatError("[!] No debug register\n");
		return false;
	}

	//
	// Set corresponding DR
	switch (m_regIdx)
	{
	case 0:
		ctx->Dr0 = m_address;
		break;
	case 1:
		ctx->Dr1 = m_address;
		break;
	case 2:
		ctx->Dr2 = m_address;
		break;
	case 3:
		ctx->Dr3 = m_address;
		break;
	}

	//
	// Note: Each mnemonic is 2 bits in length, so we advance as such

	//
	// Set this slot as enabled
	dr7.SetBit(m_regIdx * 2, true);
	//
	// Set the condition type of the breakpoint (16-17, 21-20, 24-25, 28-29)
	dr7.SetBits(16 + (m_regIdx * 2), (uint8_t)m_cond);
	//
	// Set the size of the breakpoint (18-19, 22-23, 26-27, 30-31)
	dr7.SetBit(18 + (m_regIdx * 2), (uint8_t)m_size);

	//
	// Debug print bits if wanted
	// dr7.PrintBits();

	ctx->Dr7 = static_cast<decltype(CONTEXT::Dr7)>(dr7.ToValue());
}

LONG WINAPI HwbpVectoredExceptionHandler(EXCEPTION_POINTERS* pException)
{
	for (auto it = s_hwbpList.begin(); it != s_hwbpList.end(); it++)
	{
		HardwareBreakpoint* bp = *it;

		if (bp->m_disabled)
			continue;

		if (bp->m_address == (std::uintptr_t)pException->ExceptionRecord->ExceptionAddress)
		{
			if (bp->m_handler.m_type != BreakpointHandlerType::None)
			{
				switch (bp->m_handler.m_type)
				{
				case BreakpointHandlerType::Hook:
					SET_INSTRUCTION_PTR(pException, std::get<void*>(bp->m_handler.m_var));
					break;
				case BreakpointHandlerType::Notify:
					std::get<BreakpointHandler::Notify_t>(bp->m_handler.m_var)(pException);
					SET_INSTRUCTION_PTR(pException, bp->m_buffer.buffer());
					break;
				}
			}
			else
			{
				SET_INSTRUCTION_PTR(pException, bp->m_buffer.buffer());
			}

			if (bp->m_runOnce)
			{
				bp->Disable();
			}

			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (pException->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) // Catch single step
		{
			if (bp->m_handler.m_type == BreakpointHandlerType::Notify)
			{
				std::get<BreakpointHandler::Notify_t>(bp->m_handler.m_var)(pException);
			}

			if (bp->m_runOnce)
			{
				bp->Disable();
			}

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

void __fastcall HwbpBaseThreadInitThunk(ULONG ulState, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam)
{
	if (ulState == 0)
	{
		for (auto it = s_hwbpList.begin(); it != s_hwbpList.end(); it++)
		{
			HardwareBreakpoint* bp = *it;

			if (bp->m_disabled)
				continue;

			if (!bp->m_singleThread)
			{
				//
				// Get the thread we're in
				HANDLE hThisThread = GetCurrentThread();

				//
				// Setup a context for GetThreadContext
				CONTEXT ctx{};
				ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

				if (!GetThreadContext(hThisThread, &ctx))
				{
					FormatError("[!] Error calling GetThreadContext (err: {})\n", GetLastError());
					continue;
				}

				//
				// Try finding and setting debug registers
				if (!bp->ModifyThreadContext(&ctx))
				{
					FormatError("[!] Error calling ModifyThreadContext (err: {})\n", GetLastError());
					continue;
				}

				// Set the new thread context
				if (!SetThreadContext(hThisThread, &ctx))
				{
					FormatError("[!] Error calling SetThreadContext (err: {})\n", GetLastError());
				}
			}
		} 
	}

	return _HwbpBaseThreadInitThunk(ulState, lpStartAddress, lpParam);
}

void HwbpTerminate()
{
	if (!s_addedHandler)
		return;

	//
	// Unhook kernel32!BaseThreadInitThunk
	UnHookExportDirect("kernel32", "BaseThreadInitThunk");

	//
	// Free hook trampoline
	VirtualFree(_HwbpBaseThreadInitThunk, 0, MEM_RELEASE);

	//
	// Disable any hardware breakpoints that may still exist
	for (auto bp : s_hwbpList)
	{
		bp->Disable();
	}

	//
	// Lastly, remove the VEH
	RemoveVectoredExceptionHandler(HwbpVectoredExceptionHandler);
}
