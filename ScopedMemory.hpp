#pragma once


class ScopedMemory
{
	void* m_mem = nullptr;
	std::size_t m_size{};

public:
	ScopedMemory() = default;

	ScopedMemory(std::size_t size, std::uint32_t prot) noexcept
		: m_mem{ VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, prot) }
		, m_size(size)
	{
	}

	~ScopedMemory() noexcept
	{
		if (valid())
			VirtualFree(m_mem, 0, MEM_RELEASE);
	}

	bool valid() const noexcept
	{
		return m_mem != nullptr;
	}

	void* buffer() const noexcept
	{
		return m_mem;
	}

	void setup(std::size_t size, std::uint32_t prot) noexcept
	{
		if (valid())
			VirtualFree(m_mem, 0, MEM_RELEASE);

		m_mem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, prot);
		m_size = size;
	}

	void copy(const void* data, std::size_t sz) noexcept
	{
		if (valid() && sz <= m_size)
			memcpy(m_mem, data, sz);
	}

	void copy(std::size_t idx, const void* data, std::size_t sz) noexcept
	{
		if (valid() && (idx + sz) <= m_size && sz <= m_size)
			memcpy(&((std::uint8_t*)m_mem)[idx], data, sz);
	}

	std::size_t size() const noexcept
	{
		return m_size;
	}
};