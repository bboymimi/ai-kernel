from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path
import re

@dataclass
class StackFrame:
    """Represents a single frame in the stack trace."""
    address: str
    symbol: str
    module: Optional[str] = None
    offset: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    is_exported: bool = True  # Whether the symbol is exported in the kernel symbol table

@dataclass
class StackTrace:
    """Represents a complete stack trace."""
    frames: List[StackFrame]
    error_type: str
    error_message: Optional[str] = None
    rip_info: Optional[dict] = None
    
    @property
    def symbols(self) -> List[str]:
        """Get list of symbols in the stack trace, including RIP symbol if available."""
        symbols = [frame.symbol.lstrip('?').strip() for frame in self.frames]
        if self.rip_symbol and self.rip_symbol not in symbols:
            symbols.insert(0, self.rip_symbol)
        return symbols

    @property
    def rip_frame(self) -> Optional[StackFrame]:
        """Get the RIP frame if available."""
        if self.rip_info:
            return StackFrame(
                address="",  # RIP address is handled differently
                symbol=self.rip_info['symbol'],
                offset=f"{self.rip_info['offset']}/{self.rip_info['size']}",
                is_exported=True
            )
        return None

    @property
    def rip_symbol(self) -> Optional[str]:
        """Get the RIP symbol if available."""
        return self.rip_info['symbol'] if self.rip_info else None
        
    @property
    def rip_offset(self) -> Optional[str]:
        """Get the RIP offset if available."""
        return self.rip_info['offset'] if self.rip_info else None
        
    @property
    def rip_size(self) -> Optional[str]:
        """Get the RIP size if available."""
        return self.rip_info['size'] if self.rip_info else None

class StackTraceParser:
    """Parser for kernel stack traces."""
    
    def parse_file(self, file_path: str) -> StackTrace:
        """Parse a stack trace from a file."""
        with open(file_path, 'r') as f:
            content = f.read()
        return self.parse(content)
    
    def parse(self, content: str) -> StackTrace:
        """Parse stack trace content."""
        lines = content.split('\n')
        frames = []
        error_type = "unknown"
        error_message = None
        rip_info = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Try to detect error type and message
            if "Kernel panic" in line:
                error_type = "kernel_panic"
                error_message = line
            elif "soft lockup" in line:
                error_type = "softlockup"
                error_message = line
            elif "KASAN: use-after-free" in line:
                error_type = "kasan_uaf"
                error_message = line
            elif "KASAN: out-of-bounds" in line:
                error_type = "kasan_oob"
                error_message = line
            elif "hung task" in line:
                error_type = "hung_task"
                error_message = line
            elif "WARNING:" in line:
                error_type = "warning"
                error_message = line
                
            # Parse RIP line
            rip_match = re.search(r'RIP:\s*[0-9a-f]+:([^+]+)\+([^/]+)/([^]\s]+)', line)
            if rip_match:
                rip_symbol = rip_match.group(1).strip()
                rip_offset = rip_match.group(2)
                rip_size = rip_match.group(3)
                rip_info = {
                    'symbol': rip_symbol,
                    'offset': rip_offset,
                    'size': rip_size
                }
                
            # Parse stack frame
            # Format examples:
            # [<ffffffff81012345>] function_name+0x123/0x456
            # [<ffffffff81012345>] ? function_name+0x123/0x456
            # [<ffffffff81012345>] function_name
            frame_match = re.search(r'\[<([0-9a-f]+)>\]\s*(\??\s*[^+]+)(?:\+([^/]+)/([^]\s]+))?', line)
            if frame_match:
                address = frame_match.group(1)
                symbol_part = frame_match.group(2).strip()
                offset_start = frame_match.group(3) if frame_match.group(3) else None
                offset_total = frame_match.group(4) if frame_match.group(4) else None
                
                # Skip frames with symbols starting with '?' as they are invalid
                if symbol_part.startswith('?'):
                    continue
                    
                # Clean up the symbol name
                symbol = symbol_part.strip()
                
                # Format offset as start/total if both parts are available
                offset = f"{offset_start}/{offset_total}" if offset_start and offset_total else None
                
                frames.append(StackFrame(
                    address=address,
                    symbol=symbol,
                    offset=offset,
                    is_exported=True  # All valid stack symbols are exported
                ))
        
        return StackTrace(frames, error_type, error_message, rip_info) 