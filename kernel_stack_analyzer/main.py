#!/usr/bin/env python3
import argparse
import asyncio
from pathlib import Path
from typing import List, Optional

from .parser import StackTraceParser
from .code_extractor import CodeExtractor
from .ai_agents import StackTraceAnalyzer
from .context import ContextAnalyzer

async def analyze_stack_trace(
    input_file: str,
    context: str,
    kernel_src_path: Optional[str] = None,
    debug: bool = False
) -> None:
    """Analyze a kernel stack trace file."""
    try:
        # Parse the stack trace
        parser = StackTraceParser()
        stack_trace = parser.parse_file(input_file)
        
        if debug:
            print("\nParsed Stack Trace:")
            print(f"Error Type: {stack_trace.error_type}")
            print(f"Error Message: {stack_trace.error_message}")

            # Display RIP information if available
            if stack_trace.rip_frame:
                print("\nRIP (Instruction Pointer):")
                print(f"Symbol: {stack_trace.rip_frame.symbol}")
                print(f"Offset: {stack_trace.rip_frame.offset}")

            print("\nStack Frames:")
            for i, frame in enumerate(stack_trace.frames, 1):
                print(f"{i}. {frame.symbol} ({frame.address})")
                if frame.offset:
                    print(f"   Offset: {frame.offset}")
                if frame.module:
                    print(f"   Module: {frame.module}")
                if frame.file:
                    print(f"   File: {frame.file}:{frame.line}")
        
        # Extract source code for symbols
        extractor = CodeExtractor(kernel_src_path)
        code_contexts = await extractor.extract_code_for_symbols(stack_trace.symbols)
        
        # Analyze with AI only if not in debug mode
        if not debug:
            analyzer = StackTraceAnalyzer(debug=debug)
            context_analyzer = ContextAnalyzer(context, debug=debug)
            
            # Get analysis results
            analysis = await analyzer.analyze(stack_trace, code_contexts)
            context_analysis = await context_analyzer.analyze(analysis)
            
            # Display results
            print("\nAnalysis Results\n")
            print("Stack Trace Analysis:")
            print(analysis)
            print("\nContext Analysis:")
            print(context_analysis)
        else:
            analyzer = StackTraceAnalyzer(debug=True)
            context_analyzer = ContextAnalyzer(context, debug=True)
            
            # Get prompt information
            analysis_info = await analyzer.analyze(stack_trace, code_contexts)
            context_info = await context_analyzer.analyze(analysis_info)
            
            # Display debug information
            print("\nDebug Mode: OpenAI API Call Information")
            print("\nStack Trace Analysis Call:")
            print(f"Model: {analysis_info['model']}")
            print(f"Temperature: {analysis_info['temperature']}")
            print(f"Max Tokens: {analysis_info['max_tokens']}")
            print("\nSystem Message:")
            print(analysis_info['system_message'])
            print("\nPrompt:")
            print(analysis_info['prompt'])
        
    except Exception as e:
        print(f"Error: {str(e)}")
        raise

def main():
    arg_parser = argparse.ArgumentParser(description="Analyze kernel stack traces using AI")
    arg_parser.add_argument("--input", required=True, help="Input stack trace file")
    arg_parser.add_argument("--kernel-src", help="Path to kernel source code")
    arg_parser.add_argument("--debug", action="store_true", help="Print debug information")
    
    args = arg_parser.parse_args()
    
    # Parse the stack trace once
    trace_parser = StackTraceParser()
    parsed_stack_trace_data = trace_parser.parse_file(args.input)

    # Validate that the detected error type is supported
    supported_contexts = ["kernel_panic", "softlockup", "kasan_uaf", "kasan_oob", "hung_task", "warning"]
    if parsed_stack_trace_data.error_type not in supported_contexts:
        print(f"Warning: Detected error type '{parsed_stack_trace_data.error_type}' is not supported.")
        print("Supported error types are:", ", ".join(supported_contexts))
        print("Analysis may be less accurate.")

    asyncio.run(analyze_stack_trace(args.input, parsed_stack_trace_data.error_type, args.kernel_src, args.debug))

if __name__ == "__main__":
    main() 