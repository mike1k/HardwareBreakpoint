#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string_view>
#include <vector>
#include <functional>
#include <optional>
#include <variant>

#if defined(_DEBUG)
	#define HWBP_DEBUG
#endif

#if defined(_WIN64)
	#define HWBP_X64
#else
	#define HWBP_X86
#endif

#include "BitSet.hpp"
#include "ScopedHandle.hpp"
#include "ScopedMemory.hpp"
#include "Debug.hpp"
#include "hde.hpp"
#include "EATHook.hpp"

enum class BreakpointCondition : std::uint8_t
{
	Execute		= 0b00,
	Read		= 0b01,
	ReadWrite	= 0b11,
	IOReadWrite = 0b10 // Not supported
};

enum class BreakpointLength : std::uint8_t
{
	OneByte		= 0b00,
	TwoByte		= 0b01, // Address in corresponding DR must be word aligned
	FourByte	= 0b11, // Address must be dword aligned
	EightByte	= 0b10  // Address in corresponding DR must be qword aligned
};

enum class BreakpointHandlerType : std::uint8_t
{
	None = 0,
	Hook,
	Notify		
};

struct BreakpointHandler
{
	using Notify_t = std::function<void(EXCEPTION_POINTERS*)>;
	using Hook_t = void*;
	 
	BreakpointHandler() = default;
	~BreakpointHandler() = default; 

	BreakpointHandlerType m_type = BreakpointHandlerType::None;
	std::variant<Notify_t, Hook_t> m_var;
};

class HardwareBreakpoint
{
	friend LONG WINAPI HwbpVectoredExceptionHandler(EXCEPTION_POINTERS* pException);
	friend void __fastcall HwbpBaseThreadInitThunk(ULONG ulState, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam);

public:
	//! No default or copy constructor
	HardwareBreakpoint(const HardwareBreakpoint&) = delete;
	HardwareBreakpoint(bool singleThread = false, bool runOnce = false);
	~HardwareBreakpoint();

	//! Instantiate a Hardware Breakpoint
	bool Create(void* address, BreakpointLength size, BreakpointCondition cond, std::optional<BreakpointHandler> handler = std::nullopt) noexcept;

	//! Disable this hardware breakpoint
	void Disable() noexcept;

	//! Get buffer pointer
	void* GetBuffer() const noexcept
	{
		return m_buffer.buffer();
	}

private:
	bool ModifyThreadContext(CONTEXT* ctx) noexcept;

	//! Execute a function for each thread
	template<typename TFunc>
	void ForEachThread(TFunc f);

private:
	//! Address to set an exception on
	std::uintptr_t		m_address{};
	//! Appropriated size of the breakpoint
	BreakpointLength	m_size{};
	//! Condition to break on (r/rw/ex)
	BreakpointCondition m_cond{};
	//! Occupied register index (or -1 if none)
	std::int32_t		m_regIdx{-1};
	//! Memory that holds instruction buffer
	ScopedMemory		m_buffer{};
	//! Breakpoint handler for notification/hooks
	BreakpointHandler	m_handler;
	//! Run on this thread only, or all?
	bool				m_singleThread{};
	//! Disable after the breakpoint is hit once
	bool				m_runOnce{};
	//! Currently disabled?
	bool				m_disabled{};
};

template<typename TFunc>
inline void HardwareBreakpoint::ForEachThread(TFunc f)
{
	ScopedHandle hSnapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId()) };
	if (!hSnapshot.valid())
		return;

	THREADENTRY32 te32{};
	te32.dwSize = sizeof(te32);

	if (Thread32First(hSnapshot, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == GetCurrentProcessId())
			{
				ScopedHandle hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
				if (hThread.valid())
					f(hThread);
			}
		} while (Thread32Next(hSnapshot, &te32));
	}
}

void HwbpTerminate();