#pragma once

class ScopedHandle
{
	HANDLE m_handle = INVALID_HANDLE_VALUE;

public:
	ScopedHandle() = default;


	ScopedHandle(HANDLE handle) noexcept
		: m_handle(handle)
	{
	}

	~ScopedHandle() noexcept
	{
		if (valid())
			CloseHandle(m_handle);
	}

	bool valid() const noexcept
	{
		return m_handle != INVALID_HANDLE_VALUE;
	}

	operator HANDLE () {
		return m_handle;
	}

	operator LPHANDLE () {
		return &m_handle;
	}
};