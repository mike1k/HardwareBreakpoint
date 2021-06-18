#pragma once

#include <string_view>
#include <format>
 
template< class... Args >
__forceinline void FormatError(std::string_view fmt, Args&&... args) noexcept
{
#ifdef HWBP_DEBUG
    std::cerr << std::format(fmt, std::forward<Args>(args)...);
#endif
}

template<class... Args>
__forceinline void FormatMsg(std::string_view fmt, Args&&... args) noexcept
{
#ifdef HWBP_DEBUG
    std::cout << std::format(fmt, std::forward<Args>(args)...);
#endif
}