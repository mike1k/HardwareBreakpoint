#pragma once

#if defined(HWBP_X86)
#include "hde/hde32/include/hde32.h"

using hde_t = hde32s;

inline auto hde_disasm(void* p, hde_t* hde) {
	return hde32_disasm(p, hde);
}

#else
#include "hde/hde64/include/hde64.h"

using hde_t = hde64s;

inline auto hde_disasm(void* p, hde_t* hde) {
	return hde64_disasm(p, hde);
}

#endif