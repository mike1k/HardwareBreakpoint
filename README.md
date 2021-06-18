# HardwareBreakpoint
X86/X64 Hardware Breakpoint Manager

# Goal
I wanted to create a flexible, hardware breakpoint system that can be easily dropped into projects without the reliance of multiple dependencies. 

# Usage

In order to establish a hardware breakpoint, the class `HardwareBreakpoint` must be instantiated. The constructor takes two arguments.

| Argument | Description |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| singleThread | Determines whether the breakpoint should only exist on the current thread, if set to false, every thread including newly spawned threads will be modified. |
| runOnce | Determines if the breakpoint should be disabled after it is hit once. |

Once the class is made, breakpoints can be created. Optionally, a `BreakpointHandler` can be added to `HardwareBreakpoint::Create`. BreakpointHandlers are hooks or notifications used when the breakpoint is hit.

# Example

Multiple examples are included in [Main.cpp](https://github.com/ayyMike/HardwareBreakpoint/blob/main/Main.cpp).

# Sources

https://en.wikipedia.org/wiki/X86_debug_register

https://wiki.osdev.org/CPU_Registers_x86-64#DR7

http://x86asm.net/articles/debugging-in-amd64-64-bit-mode-in-theory/


