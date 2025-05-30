#!/usr/bin/env python3
import os
import asyncio
from typing import Optional
from fastmcp import FastMCP

# Handle both module and direct execution imports
try:
    from .parser import StackTraceParser
    from .code_extractor import CodeExtractor
    from .ai_agents import StackTraceAnalyzer
except ImportError:
    from parser import StackTraceParser
    from code_extractor import CodeExtractor
    from ai_agents import StackTraceAnalyzer

mcp = FastMCP(server_id="kernel-stack-analyzer-fastmcp", title="Kernel Stack Analyzer Server")

@mcp.tool()
async def analyze_kernel_stack(
    coredump_message: str,
    kernel_src_path: Optional[str] = None
) -> dict:
    """
    Analyze kernel stack trace from coredump messages and generate a prompt for LLM analysis.

    Args:
        coredump_message: The kernel coredump/panic message containing the call stack
        Please ask the user to provide Linux kernel source code version if there is no version in the message.
        Specifically for the callstack, please must be sure to format the coredump message into the following format or the parser will not work.
        If the RIP doesn't exist, you can make up one by the first function
        symbol. In the following example, the callstack wiout RIP and the RIP is
        [ 4561.892744][ T3597]  vcpu_run+0xac2/0x6990, which is the first
        function symbol.
        For example:
        RIP: 0010:split_huge_pmd_locked+0x3b5/0x2b60
        Call Trace:
        <TASK>
        [\d+\.\d+][\s*T\d+]\s*\w\+.*\/.*

        ```
        Call Trace:
        RIP: 0010:vcpu_run+0xac2/0x6990
        <TASK>
        [ 4561.892744][ T3597]  vcpu_run+0xac2/0x6990
        [ 4561.893210][ T3597]  ? __pfx___calc_delta+0x10/0x10
        [ 4561.893825][ T3597]  ? __pfx_vcpu_run+0x10/0x10
        [ 4561.894411][ T3597]  ? __local_bh_enable_ip+0x11a/0x1a0
        [ 4561.894971][ T3597]  ? __pfx___local_bh_enable_ip+0x10/0x10
        [ 4561.895578][ T3597]  ? lock_acquire+0xf5/0x290
        [ 4561.896067][ T3597]  ? kvm_arch_vcpu_ioctl_run+0x219/0x19c0
        [ 4561.896666][ T3597]  kvm_arch_vcpu_ioctl_run+0x10ec/0x19c0
        [ 4561.897250][ T3597]  ? __pfx_stack_trace_save+0x10/0x10
        [ 4561.897817][ T3597]  ? kvm_arch_vcpu_ioctl_run+0x219/0x19c0
        [ 4561.898413][ T3597]  ? __pfx_kvm_arch_vcpu_ioctl_run+0x10/0x10
        [ 4561.899037][ T3597]  ? lockdep_unlock+0x74/0x100
        [ 4561.899533][ T3597]  ? __lock_acquire+0x2602/0x3170
        [ 4561.900074][ T3597]  ? kvm_vcpu_ioctl+0xbc8/0xe80
        [ 4561.900585][ T3597]  ? __mutex_unlock_slowpath+0x1b8/0x710
        [ 4561.901175][ T3597]  ? kvm_vcpu_ioctl+0x25a/0xe80
        [ 4561.901689][ T3597]  ? do_raw_write_lock+0x122/0x260
        [ 4561.902227][ T3597]  ? lock_acquire+0xf5/0x290
        [ 4561.902709][ T3597]  ? __pfx_do_raw_write_lock+0x10/0x10
        [ 4561.903295][ T3597]  kvm_vcpu_ioctl+0x9b2/0xe80
        [ 4561.903829][ T3597]  ? __pfx_kvm_vcpu_ioctl+0x10/0x10
        [ 4561.904386][ T3597]  ? schedule+0x158/0x330
        [ 4561.904839][ T3597]  ? exc_page_fault+0x64/0x100
        [ 4561.905346][ T3597]  ? __pfx___schedule+0x10/0x10
        [ 4561.905850][ T3597]  ? do_user_addr_fault+0xe03/0x1490
        [ 4561.906400][ T3597]  ? __phys_addr+0xbf/0x170
        [ 4561.906889][ T3597]  ? fput_close_sync+0x134/0x210
        [ 4561.907425][ T3597]  ? __pfx_kvm_vcpu_ioctl+0x10/0x10
        [ 4561.907967][ T3597]  __se_sys_ioctl+0xfe/0x170
        [ 4561.908460][ T3597]  do_syscall_64+0x6a/0x120
        ```
        kernel_src_path: Path to the Linux kernel source tree (optional, uses KERNEL_SRC_PATH env var if not provided)

    Returns:
        A dictionary containing:
        - error_type: The detected error type (kernel_panic, softlockup, kasan_uaf, etc.)
        - error_message: The error message from the coredump
        - symbols: List of function symbols in the stack trace
        - prompt: The generated prompt for LLM analysis with function source code
        - code_contexts: Dictionary mapping symbols to their source code
    """
    print(f"[Tool Call] analyze_kernel_stack()")
    print(f"coredump_message: {coredump_message}")

    # Use provided kernel source path or fall back to environment variable
    if not kernel_src_path:
        kernel_src_path = os.getenv("KERNEL_SRC_PATH", "/home/gavin/os/work_kernel")

    # Parse the stack trace
    parser = StackTraceParser()
    stack_trace = parser.parse(coredump_message)

    # Extract code for symbols
    extractor = CodeExtractor(kernel_src_path)
    code_contexts = await extractor.extract_code_for_symbols(stack_trace.symbols)

    # Generate analysis prompt
    analyzer = StackTraceAnalyzer(debug=True)  # Use debug mode to get prompt without calling OpenAI
    analysis_result = await analyzer.analyze(stack_trace, code_contexts)

    # Return structured result
    return {
        "error_type": stack_trace.error_type,
        "error_message": stack_trace.error_message,
        "symbols": stack_trace.symbols,
        "rip_info": stack_trace.rip_info,
        "prompt": analysis_result["prompt"],
        "system_message": analysis_result["system_message"],
        "code_contexts": code_contexts,
        "stack_frames": [
            {
                "symbol": frame.symbol,
                "offset": frame.offset,
                "module": frame.module,
                "file": frame.file,
                "line": frame.line
            }
            for frame in stack_trace.frames
        ]
    }

if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport="streamable-http", host="127.0.0.1", port=8080, path="/mcp")
