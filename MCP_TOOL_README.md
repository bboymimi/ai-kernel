# Kernel Stack Analyzer MCP Tool

## Overview

The `analyze_kernel_stack` MCP tool is designed to help LLMs analyze Linux kernel coredump messages by automatically:
1. Parsing kernel stack traces
2. Extracting source code for functions in the call stack using cscope
3. Generating comprehensive prompts for further LLM analysis

## How to set up the tool

```bash
git clone https://github.com/gavin-li/kernel-stack-analyzer.git
cd kernel-stack-analyzer
pip install -r requirements.txt
uv run kernel_stack_analyzer/mcp_server.py
home/gavin/os/ai-kernel/kernel_stack_analyzer/mcp_server.py:17: DeprecationWarning: Passing runtime and transport-specific settings as kwargs to the FastMCP constructor is deprecated (as of 2.3.4), including most transport se
ttings. If possible, provide settings when calling run() instead.
  mcp = FastMCP(server_id="kernel-stack-analyzer-fastmcp", title="Kernel Stack Analyzer Server")
[05/29/25 14:05:20] INFO     Starting MCP server 'FastMCP' with transport 'streamable-http' on http://127.0.0.1:8080/mcp server.py:823
INFO:     Started server process [4038757]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8080 (Press CTRL+C to quit)
```

Then, you would need to export the port forwarding for the MCP server with a public IP address.
Or you can use the following command to get the public domain name and port forwarding.

```bash
cloudflared tunnel --url http://127.0.0.1:8080/mcp
```

After that, you can use the public domain name in Cursor or any LLM client.



## Tool Signature

```python
@mcp.tool()
async def analyze_kernel_stack(
    coredump_message: str,
    kernel_src_path: Optional[str] = None
) -> dict
```

### Parameters

- `coredump_message` (str, required): The kernel coredump/panic message containing the call stack
- `kernel_src_path` (str, optional): Path to the Linux kernel source tree. If not provided, uses `KERNEL_SRC_PATH` environment variable or defaults to `/usr/src/linux`

### Returns

A dictionary containing:
- `error_type`: The detected error type (kernel_panic, softlockup, kasan_uaf, kasan_oob, hung_task, warning, unknown)
- `error_message`: The error message from the coredump
- `symbols`: List of function symbols in the stack trace
- `rip_info`: RIP (instruction pointer) information if available
- `prompt`: The generated prompt for LLM analysis with function source code
- `system_message`: System message for the LLM
- `code_contexts`: Dictionary mapping symbols to their source code
- `stack_frames`: Detailed information about each stack frame

## Usage Scenario

When an LLM receives a kernel coredump message from a user, it should:

1. **Detect the kernel stack trace** in the user's message
2. **Call the MCP tool** with the coredump message
3. **Use the generated prompt** for detailed analysis

### Example Workflow

```python
# User provides kernel coredump
user_message = """
My system crashed with this error:
[ 4561.875466][ T3597] WARNING: CPU: 1 PID: 3597 at arch/x86/kvm/lapic.c:3384 kvm_apic_accept_events+0x3ad/0x510
...
Call Trace:
 kvm_apic_accept_events+0x3ad/0x510
 kvm_arch_vcpu_ioctl_run+0x1bd0/0x2b70
...
"""

# LLM detects kernel stack trace and calls the tool
result = await analyze_kernel_stack(coredump_message=user_message)

# LLM uses the generated prompt for analysis
# result['system_message'] contains: "You are an expert kernel developer analyzing stack traces."
# result['prompt'] contains the full analysis prompt with source code
```

## Prerequisites

1. **Linux kernel source tree**: The tool needs access to the kernel source code
2. **Cscope database**: Run `make cscope` in the kernel source directory to generate the cscope database
3. **Environment setup**: Set `KERNEL_SRC_PATH` environment variable to point to your kernel source

```bash
export KERNEL_SRC_PATH=/path/to/linux-kernel-source
cd $KERNEL_SRC_PATH
make cscope
```

## Supported Error Types

The tool automatically detects the following kernel error types:
- `kernel_panic`: Kernel panic errors
- `softlockup`: Soft lockup detected
- `kasan_uaf`: KASAN use-after-free errors
- `kasan_oob`: KASAN out-of-bounds errors
- `hung_task`: Hung task errors
- `warning`: Kernel warnings
- `unknown`: Unrecognized error types

## Generated Prompt Structure

The tool generates a comprehensive prompt that includes:

1. **Error context**: Type and message
2. **RIP information**: Instruction pointer details and source code
3. **Stack trace**: Each function in the call stack
4. **Source code**: Actual implementation of functions in the trace
5. **Analysis guidelines**: Structured questions for the LLM to answer

## Example Output

```
Error Type: warning
Error Message: WARNING: CPU: 1 PID: 3597 at arch/x86/kvm/lapic.c:3384 kvm_apic_accept_events+0x3ad/0x510

Instruction Pointer (RIP):
Symbol: kvm_apic_accept_events
Offset: 0x3ad/0x510

RIP Symbol Code:
// File: arch/x86/kvm/lapic.c
// Line: 3384
[actual function code here]

Stack Trace:
1. kvm_apic_accept_events +0x3ad/0x510
   Code: [function implementation]

2. kvm_arch_vcpu_ioctl_run +0x1bd0/0x2b70
   Code: [function implementation]
...

Please provide:
1. A high-level summary of what this stack trace represents
2. Analysis of the code at the RIP location
3. The sequence of events that led to this error
4. Potential root causes based on the code analysis
5. Suggestions for debugging or fixing the issue
```

## Integration with LLMs

LLMs should use this tool when they:
- Receive kernel panic or crash dumps
- Need to analyze kernel stack traces
- Want to understand the code flow leading to a kernel error
- Need to provide debugging suggestions for kernel issues

The tool handles the complex parsing and code extraction, allowing the LLM to focus on the actual analysis and providing helpful insights to the user.
