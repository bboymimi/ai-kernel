#!/usr/bin/env python3
"""
Test script for the analyze_kernel_stack MCP tool.
This demonstrates how an LLM would use the tool when it detects a kernel stack trace.
"""

import asyncio
import json
import unittest
from kernel_stack_analyzer.mcp_server import analyze_kernel_stack

# Example kernel coredump message with stack trace
EXAMPLE_COREDUMP = """
[ 4561.875466][ T3597] WARNING: CPU: 1 PID: 3597 at arch/x86/kvm/lapic.c:3384 kvm_apic_accept_events+0x3ad/0x510
[ 4561.875471][ T3597] Modules linked in: kvm_intel kvm irqbypass
[ 4561.875476][ T3597] CPU: 1 UID: 0 PID: 3597 Comm: qemu-system-x86 Not tainted 6.12.0-rc7+ #1
[ 4561.875478][ T3597] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-5 04/01/2014
[ 4561.875479][ T3597] RIP: 0010:kvm_apic_accept_events+0x3ad/0x510
[ 4561.875482][ T3597] Code: 0f 0b e9 b5 fd ff ff 0f 0b e9 ae fd ff ff 44 89 e6 48 c7 c7 40 f9 fd 85 e8 6e 2e 5f 00 e9 9a fd ff ff 0f 0b e9 93 fd ff ff <0f> 0b e9 8c fd ff ff 4c 89 ef e8 e3 e6 ff ff e9 47 ff ff ff e8 f9
[ 4561.875483][ T3597] RSP: 0018:ffffc90001a0fcc8 EFLAGS: 00010202
[ 4561.875485][ T3597] RAX: 0000000000000000 RBX: ffff88810c3c8000 RCX: 0000000000000001
[ 4561.875486][ T3597] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffff88810c3c8000
[ 4561.875487][ T3597] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[ 4561.875488][ T3597] R10: 0000000000000000 R11: 0000000000000000 R12: ffff88810c3c8000
[ 4561.875489][ T3597] R13: 0000000000000000 R14: ffff88810c3c8000 R15: 0000000000000000
[ 4561.875490][ T3597] FS:  00007f2e2ffff6c0(0000) GS:ffff88813bc80000(0000) knlGS:0000000000000000
[ 4561.875491][ T3597] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[ 4561.875492][ T3597] CR2: 00007f2e300c5008 CR3: 000000010c6fa006 CR4: 0000000000770ef0
[ 4561.875495][ T3597] PKRU: 55555554
[ 4561.875496][ T3597] Call Trace:
[ 4561.875497][ T3597]  <TASK>
[ 4561.875499][ T3597]  ? __warn+0xd5/0x1d0
[ 4561.875503][ T3597]  ? kvm_apic_accept_events+0x3ad/0x510
[ 4561.875505][ T3597]  ? report_bug+0x1c5/0x1f0
[ 4561.875509][ T3597]  ? handle_bug+0x42/0x70
[ 4561.875512][ T3597]  ? exc_invalid_op+0x1a/0x50
[ 4561.875514][ T3597]  ? asm_exc_invalid_op+0x1a/0x20
[ 4561.875518][ T3597]  ? kvm_apic_accept_events+0x3ad/0x510
[ 4561.875520][ T3597]  ? kvm_apic_accept_events+0x3ad/0x510
[ 4561.875523][ T3597]  kvm_arch_vcpu_ioctl_run+0x1bd0/0x2b70
[ 4561.875527][ T3597]  ? kvm_arch_vcpu_ioctl_run+0x1bd0/0x2b70
[ 4561.875530][ T3597]  kvm_vcpu_ioctl+0x54f/0x630
[ 4561.875533][ T3597]  ? vfs_write+0x415/0x4d0
[ 4561.875537][ T3597]  __x64_sys_ioctl+0xb8/0xf0
[ 4561.875540][ T3597]  x64_sys_call+0x189c/0x20d0
[ 4561.875543][ T3597]  do_syscall_64+0x64/0x130
[ 4561.875546][ T3597]  ? do_syscall_64+0x70/0x130
[ 4561.875548][ T3597]  ? do_syscall_64+0x70/0x130
[ 4561.875550][ T3597]  ? do_syscall_64+0x70/0x130
[ 4561.875552][ T3597]  entry_SYSCALL_64_after_hwframe+0x4b/0x53
[ 4561.875555][ T3597] RIP: 0033:0x7f2e3451190f
"""

class TestMCPAnalyzer(unittest.IsolatedAsyncioTestCase):
    async def test_analyze_kernel_stack_output(self):
        """Test the analyze_kernel_stack MCP tool output format and content."""
        print("\nTesting analyze_kernel_stack MCP tool output...")
        print("=" * 80)

        # Call the MCP tool
        result = await analyze_kernel_stack(
            coredump_message=EXAMPLE_COREDUMP,
            kernel_src_path=None  # Will use KERNEL_SRC_PATH env var or default
        )

        # Display results - these are for manual verification during test development/debugging
        # For automated tests, you'd use self.assert... methods
        print(f"\nError Type: {result['error_type']}")
        print(f"Error Message: {result['error_message']}")

        print(f"\nDetected Symbols ({len(result['symbols'])}):")
        for i, symbol in enumerate(result['symbols'], 1):
            print(f"  {i}. {symbol}")

        if result['rip_info']:
            print(f"\nRIP Information:")
            print(f"  Symbol: {result['rip_info']['symbol']}")
            offset = result['rip_info']['offset']
            size = result['rip_info']['size']
            if size and size != '0x0':
                print(f"  Offset: {offset}/{size}")
            else:
                print(f"  Offset: {offset}")
            if 'file' in result['rip_info']:
                print(f"  File: {result['rip_info']['file']}:{result['rip_info']['line']}")

        print(f"\nStack Frames ({len(result['stack_frames'])}):")
        for i, frame in enumerate(result['stack_frames'], 1):
            print(f"  {i}. {frame['symbol']}")
            if frame['offset']:
                print(f"     Offset: {frame['offset']}")
            if frame['module']:
                print(f"     Module: {frame['module']}")

        print("\n" + "=" * 80)
        print("Generated Prompt for LLM Analysis:")
        print("=" * 80)
        print(f"\nSystem Message: {result['system_message']}")
        print(f"\nUser Prompt:\n{result['prompt']}")

        # Show code contexts summary
        print("\n" + "=" * 80)
        print("Code Contexts Summary:")
        print("=" * 80)
        for symbol, code in result['code_contexts'].items():
            lines = code.split('\n')
            print(f"\n{symbol}:")
            if "Could not find" in code or "Error" in code or "Failed" in code:
                print(f"  {lines[0]}")
            else:
                print(f"  {lines[0]}")  # File info
                if len(lines) > 1:
                    print(f"  {lines[1]}")  # Line info
                print(f"  ... ({len(lines)} lines of code)")

        # Example Assertions (you should tailor these to your specific needs)
        self.assertIsNotNone(result, "Result should not be None")
        self.assertIn('error_type', result, "Result should contain 'error_type'")
        self.assertEqual(result['error_type'], "warning", "Error type should be warning for this example")
        self.assertIn('symbols', result, "Result should contain 'symbols'")
        self.assertTrue(len(result['symbols']) > 0, "Should detect symbols")
        self.assertIn('prompt', result, "Result should contain 'prompt'")
        self.assertIn('code_contexts', result, "Result should contain 'code_contexts'")

# To run this test:
# From the project root directory:
# python -m unittest tests.test_mcp_analyzer
# or
# uv run python -m unittest tests.test_mcp_analyzer
