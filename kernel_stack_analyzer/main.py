#!/usr/bin/env python3
import argparse
import asyncio
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from .parser import StackTraceParser
from .code_extractor import CodeExtractor
from .ai_agents import StackTraceAnalyzer
from .context import ContextAnalyzer

console = Console()

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
            console.print("\n[bold yellow]Parsed Stack Trace:[/bold yellow]")
            console.print(f"Error Type: {stack_trace.error_type}")
            console.print(f"Error Message: {stack_trace.error_message}")

            # Display RIP information if available
            if stack_trace.rip_frame:
                console.print("\n[bold red]RIP (Instruction Pointer):[/bold red]")
                console.print(f"Symbol: {stack_trace.rip_frame.symbol}")
                console.print(f"Offset: {stack_trace.rip_frame.offset}")

            console.print("\n[bold yellow]Stack Frames:[/bold yellow]")
            for i, frame in enumerate(stack_trace.frames, 1):
                console.print(f"{i}. {frame.symbol} ({frame.address})")
                if frame.offset:
                    console.print(f"   Offset: {frame.offset}")
                if frame.module:
                    console.print(f"   Module: {frame.module}")
                if frame.file:
                    console.print(f"   File: {frame.file}:{frame.line}")
        
        # Extract source code for symbols
        extractor = CodeExtractor(kernel_src_path)
        code_contexts = await extractor.extract_code_for_symbols(stack_trace.symbols)
        
        if debug:
            console.print("\n[bold yellow]Extracted Code Contexts:[/bold yellow]")

            # Display RIP code context first if available
            if stack_trace.rip_symbol and stack_trace.rip_symbol in code_contexts:
                console.print("\n[bold red]RIP Symbol Code:[/bold red]")
                console.print(Syntax(code_contexts[stack_trace.rip_symbol], "c", theme="monokai"))

            # Display other code contexts
            for symbol, code in code_contexts.items():
                if symbol != stack_trace.rip_symbol:  # Skip RIP symbol as it's already shown
                    console.print(f"\n[bold]{symbol}:[/bold]")
                    console.print(Syntax(code, "c", theme="monokai"))
        
        # Analyze with AI only if not in debug mode
        if not debug:
            analyzer = StackTraceAnalyzer(debug=debug)
            context_analyzer = ContextAnalyzer(context, debug=debug)
            
            # Get analysis results
            analysis = await analyzer.analyze(stack_trace, code_contexts)
            context_analysis = await context_analyzer.analyze(analysis)
            
            # Display results
            console.print(Panel.fit(
                f"[bold green]Analysis Results[/bold green]\n\n"
                f"[bold]Stack Trace Analysis:[/bold]\n{analysis}\n\n"
                f"[bold]Context Analysis:[/bold]\n{context_analysis}",
                title="Kernel Stack Trace Analysis"
            ))
        else:
            analyzer = StackTraceAnalyzer(debug=True)
            context_analyzer = ContextAnalyzer(context, debug=True)
            
            # Get prompt information
            analysis_info = await analyzer.analyze(stack_trace, code_contexts)
            context_info = await context_analyzer.analyze(analysis_info)
            
            # Display debug information
            console.print("\n[bold yellow]Debug Mode: OpenAI API Call Information[/bold yellow]")
            console.print("\n[bold cyan]Stack Trace Analysis Call:[/bold cyan]")
            console.print(f"Model: {analysis_info['model']}")
            console.print(f"Temperature: {analysis_info['temperature']}")
            console.print(f"Max Tokens: {analysis_info['max_tokens']}")
            console.print("\n[bold magenta]System Message:[/bold magenta]")
            console.print(analysis_info['system_message'])
            console.print("\n[bold green]Prompt:[/bold green]")
            console.print(Syntax(analysis_info['prompt'], "markdown"))
            
            console.print("\n[bold cyan]Context Analysis Call:[/bold cyan]")
            console.print(f"Model: {context_info['model']}")
            console.print(f"Temperature: {context_info['temperature']}")
            console.print(f"Max Tokens: {context_info['max_tokens']}")
            console.print("\n[bold magenta]System Message:[/bold magenta]")
            console.print(context_info['system_message'])
            console.print("\n[bold green]Prompt:[/bold green]")
            console.print(Syntax(context_info['prompt'], "markdown"))
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise

def main():
    parser = argparse.ArgumentParser(description="Analyze kernel stack traces using AI")
    parser.add_argument("--input", required=True, help="Input stack trace file")
    parser.add_argument("--context", required=True, choices=[
        "kernel_panic", "softlockup", "kasan_uaf", "kasan_oob", "hung_task"
    ], help="Type of kernel error context")
    parser.add_argument("--kernel-src", help="Path to kernel source code")
    parser.add_argument("--debug", action="store_true", help="Print debug information")
    
    args = parser.parse_args()
    
    asyncio.run(analyze_stack_trace(args.input, args.context, args.kernel_src, args.debug))

if __name__ == "__main__":
    main() 