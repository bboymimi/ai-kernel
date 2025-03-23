import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import subprocess
import re
import os
from rich.console import Console

class CodeExtractor:
    """Extracts source code for kernel symbols."""
    
    def __init__(self, kernel_src_path: Optional[str] = None):
        self.kernel_src_path = Path(kernel_src_path) if kernel_src_path else None
        self.console = Console()
        self.cscope_db_path = None
        
    async def setup_cscope(self) -> bool:
        """Set up cscope database for the kernel source."""
        if not self.kernel_src_path or not self.kernel_src_path.exists():
            return False
            
        try:
            # Check if cscope.out exists
            cscope_out = self.kernel_src_path / "cscope.out"
            if cscope_out.exists():
                self.cscope_db_path = str(cscope_out)
                return True
                
            self.console.print("[red]No cscope database found. Please run 'make cscope' in the kernel source directory.[/red]")
            return False
            
        except Exception as e:
            self.console.print(f"[red]Error setting up cscope: {str(e)}[/red]")
            return False
        
    async def extract_code_for_symbols(self, symbols: List[str]) -> Dict[str, str]:
        """Extract source code for a list of symbols."""
        if not self.kernel_src_path:
            return {symbol: "Kernel source path not provided" for symbol in symbols}
            
        # Set up cscope if needed
        if not await self.setup_cscope():
            return {symbol: "Failed to set up cscope database" for symbol in symbols}
            
        results = {}
        for symbol in symbols:
            # Clean up symbol name (remove ? prefix if present)
            clean_symbol = symbol.lstrip('?').strip()
            
            # Try to find the symbol in different locations
            code = await self._extract_code_for_symbol(clean_symbol)
            
            # If not found, try architecture-specific locations
            if "Could not find source location" in code:
                code = await self._extract_arch_specific_code(clean_symbol)
            
            results[symbol] = code
            
        return results
    
    async def _extract_code_for_symbol(self, symbol: str) -> str:
        """Extract source code for a single symbol."""
        try:
            # First try exact symbol match
            location = await self._find_symbol_location(symbol)
            if not location:
                # Try partial match if exact match fails
                location = await self._find_symbol_location(symbol, partial=True)
                
            if not location:
                return f"Could not find source location for symbol: {symbol}"
                
            file_path, line_num = location
            
            # Read the function code
            return await self._read_function_code(file_path, line_num)
            
        except Exception as e:
            return f"Error extracting code for {symbol}: {str(e)}"
    
    async def _extract_arch_specific_code(self, symbol: str) -> str:
        """Try to find the symbol in architecture-specific code."""
        try:
            # Common locations for architecture-specific code
            arch_paths = [
                "arch/x86",  # x86-specific code
                "arch/x86/entry",  # Entry points and interrupts
                "arch/x86/mm",  # Memory management
                "arch/x86/kernel",  # Core kernel code
            ]
            
            for arch_path in arch_paths:
                # Try to find the symbol in assembly files
                asm_files = await self._find_asm_files(arch_path)
                for asm_file in asm_files:
                    if await self._find_symbol_in_asm(asm_file, symbol):
                        return await self._read_asm_code(asm_file, symbol)
            
            return f"Could not find architecture-specific code for symbol: {symbol}"
            
        except Exception as e:
            return f"Error extracting architecture-specific code for {symbol}: {str(e)}"
    
    async def _find_asm_files(self, arch_path: str) -> List[str]:
        """Find assembly files in the given architecture path."""
        try:
            find_cmd = [
                "find",
                str(self.kernel_src_path / arch_path),
                "-name", "*.S",
                "-o", "-name", "*.s"
            ]
            
            result = subprocess.run(find_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                return [f for f in result.stdout.strip().split('\n') if f]
            return []
            
        except Exception:
            return []
    
    async def _find_symbol_in_asm(self, asm_file: str, symbol: str) -> bool:
        """Check if a symbol is defined in an assembly file."""
        try:
            with open(asm_file, 'r') as f:
                content = f.read()
                # Look for common assembly symbol definitions
                patterns = [
                    rf'ENTRY\({re.escape(symbol)}\)',
                    rf'GLOBAL\({re.escape(symbol)}\)',
                    rf'\.globl\s+{re.escape(symbol)}',
                    rf'{re.escape(symbol)}:',
                ]
                return any(re.search(pattern, content) for pattern in patterns)
        except Exception:
            return False
    
    async def _read_asm_code(self, asm_file: str, symbol: str) -> str:
        """Read assembly code for a symbol."""
        try:
            with open(asm_file, 'r') as f:
                lines = f.readlines()
            
            # Find the symbol definition
            symbol_line = -1
            for i, line in enumerate(lines):
                if re.search(rf'({symbol}:|ENTRY\({symbol}\)|GLOBAL\({symbol}\))', line):
                    symbol_line = i
                    break
            
            if symbol_line == -1:
                return f"Could not find symbol {symbol} in {asm_file}"
            
            # Include a few lines before for context
            start_line = max(0, symbol_line - 5)
            
            # Read until we find the end of the function
            end_line = symbol_line + 1
            for i in range(symbol_line + 1, len(lines)):
                line = lines[i]
                if re.search(r'ENDPROC|\.size|\.end|^[a-zA-Z_][a-zA-Z0-9_]*:', line):
                    end_line = i + 1
                    break
                end_line = i + 1
            
            header = f"// File: {asm_file}\n// Line: {symbol_line + 1}\n\n"
            return header + ''.join(lines[start_line:end_line])
            
        except Exception as e:
            return f"Error reading assembly code: {str(e)}"
    
    async def _find_symbol_location(self, symbol: str, partial: bool = False) -> Optional[Tuple[str, int]]:
        """Find source location for a symbol using cscope."""
        try:
            # Use cscope to find the symbol definition
            cscope_cmd = [
                "cscope", "-dL",
                "-1",
                symbol,
                "-f", self.cscope_db_path
            ]
            
            result = subprocess.run(
                cscope_cmd,
                capture_output=True,
                text=True,
                cwd=str(self.kernel_src_path)
            )
            
            if result.returncode != 0 or not result.stdout.strip():
                return None
                
            # Parse cscope output
            # Format: file line_number function_name
            lines = result.stdout.strip().split('\n')
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    file_path = parts[0]
                    line_num = int(parts[2])
                    
                    # Check if this is actually the function definition
                    if await self._verify_function_definition(file_path, line_num, symbol):
                        return file_path, line_num
            return None
            
        except Exception:
            return None
    
    async def _verify_function_definition(self, file_path: str, line_num: int, symbol: str) -> bool:
        """Verify that the given location is actually a function definition."""
        try:
            full_path = self.kernel_src_path / file_path
            with open(full_path, 'r') as f:
                lines = f.readlines()
                
            if line_num <= 0 or line_num > len(lines):
                return False
                
            # Look at the line and a few lines around it
            context = lines[max(0, line_num-3):min(len(lines), line_num+3)]
            context_text = ''.join(context)
            
            # Pattern for function definition (C or assembly)
            patterns = [
                # C function definition
                rf'\b{re.escape(symbol)}\s*\([^)]*\)\s*{{?',
                # Assembly entry points
                rf'ENTRY\({re.escape(symbol)}\)',
                rf'GLOBAL\({re.escape(symbol)}\)',
                rf'\.globl\s+{re.escape(symbol)}',
                rf'{re.escape(symbol)}:',
            ]
            return any(re.search(pattern, context_text) for pattern in patterns)
            
        except Exception:
            return False
    
    async def _read_function_code(self, file_path: str, start_line: int) -> str:
        """Read the function code starting from the given line."""
        try:
            full_path = self.kernel_src_path / file_path
            with open(full_path, 'r') as f:
                lines = f.readlines()
                
            # Find function boundaries
            start_idx = start_line - 1
            end_idx = start_idx
            
            # Look for function end (closing brace)
            brace_count = 0
            in_function = False
            
            for i in range(start_idx, len(lines)):
                line = lines[i]
                
                # Skip until we find the function start
                if not in_function:
                    if '{' in line:
                        in_function = True
                        brace_count = 1
                    continue
                
                brace_count += line.count('{')
                brace_count -= line.count('}')
                
                if brace_count == 0:
                    end_idx = i + 1
                    break
            
            # Include function signature and a few lines before it
            start_idx = max(0, start_idx - 3)
            
            # Extract function code
            function_code = ''.join(lines[start_idx:end_idx])
            
            # Add file and line information
            header = f"// File: {file_path}\n// Line: {start_line}\n\n"
            return header + function_code.strip()
            
        except Exception as e:
            return f"Error reading function code: {str(e)}" 