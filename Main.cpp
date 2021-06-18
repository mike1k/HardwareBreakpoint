#include "HardwareBreakpoint.hpp"

void(*_printf)(const char* szFmt, ...);
void __cdecl printf_hook(const char* szFmt, ...);

int main()
{
	//! Test BreakpointHandlerType::Notify on execution
	{
		HardwareBreakpoint breakpoint;
		//
		// Change MessageBoxA text
		BreakpointHandler handler{}; // Note: handlers are optional
		handler.m_type = BreakpointHandlerType::Notify; // No hooking, just notify when the breakpoint is hit

#if defined(HWBP_X64)
		handler.m_var = [](EXCEPTION_POINTERS* p)
		{
			printf("$ Exception caught - modifying RDX\n");

			//
			// Second argument will hold the text, so RDX
			p->ContextRecord->Rdx = reinterpret_cast<std::uintptr_t>("Changed the text!");
		};
#else
		handler.m_var = [](EXCEPTION_POINTERS* p)
		{
			printf("$ Exception caught - modifying [esp+8]\n");

			//
			// Second argument will hold the text, so [esp+8]
			*reinterpret_cast<const char**>(p->ContextRecord->Esp + 8) = "Changed the text!";
		};
#endif
		breakpoint.Create(MessageBoxA, BreakpointLength::OneByte, BreakpointCondition::Execute, handler);

		//
		// Call to test
		MessageBoxA(NULL, "Change this text!", "Test", MB_OK);
	}

	//! Test BreakpointHandlerType::Hook
	{
		HardwareBreakpoint breakpoint;
		BreakpointHandler handler{};
		handler.m_type = BreakpointHandlerType::Hook; // Redirect printf
		handler.m_var = printf_hook;

		breakpoint.Create(printf, BreakpointLength::OneByte, BreakpointCondition::Execute, handler);
		_printf = ((decltype(_printf))breakpoint.GetBuffer());

		//
		// Test printf (this will print "$ Inside printf_hook.")
		printf("This is a test.\n");
	}

	//! Test a dword/qword read/write
	{
#if defined(HWBP_X64)
		BreakpointLength bplen = BreakpointLength::EightByte;
#else
		BreakpointLength bplen = BreakpointLength::FourByte;
#endif
		std::uintptr_t dummy{};

		HardwareBreakpoint breakpoint;
		BreakpointHandler handler{};
		handler.m_type = BreakpointHandlerType::Notify;
		handler.m_var = [](EXCEPTION_POINTERS* p)
		{
#if defined(HWBP_X64)
			printf("$ Dummy was read/written - current RIP: 0x%p\n", p->ContextRecord->Rip);
#else
			printf("$ Dummy was read/written - current EIP: 0x%p\n", p->ContextRecord->Eip);
#endif
		};

		breakpoint.Create(&dummy, bplen, BreakpointCondition::ReadWrite, handler);
		
		//
		// Invoke the breakpoint
		dummy = 1337;
	}


	//
	// Clean up by calling HwbpTerminate
	HwbpTerminate();

	return getchar();
}


void __cdecl printf_hook(const char* szFmt, ...)
{
	_printf("$ Inside printf_hook.\n");
}