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
    offset: Optional[str] = None # Should include 0x prefix, e.g., 0x10 or 0x10/0x20
    file: Optional[str] = None
    line: Optional[int] = None
    is_exported: bool = True

@dataclass
class StackTrace:
    """Represents a complete stack trace."""
    frames: List[StackFrame]
    error_type: str
    error_message: Optional[str] = None
    rip_info: Optional[dict] = None # Keys: symbol, offset, size, file, line
    
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
            offset_val = self.rip_info.get('offset')
            size_val = self.rip_info.get('size')
            display_offset_str = offset_val
            if offset_val and size_val and size_val != '0x0': # Avoid x/0x0 in display
                display_offset_str = f"{offset_val}/{size_val}"

            return StackFrame(
                address=self.rip_info.get('file', '<RIP>') + (f":{self.rip_info['line']}" if 'line' in self.rip_info else ""),
                symbol=self.rip_info['symbol'],
                offset=display_offset_str,
                file=self.rip_info.get('file'),
                line=self.rip_info.get('line'),
                is_exported=True
            )
        return None

    @property
    def rip_symbol(self) -> Optional[str]:
        """Get the RIP symbol if available."""
        return self.rip_info['symbol'] if self.rip_info else None
        
    @property
    def rip_offset(self) -> Optional[str]: # Returns only the offset part, e.g. 0x3ad
        if self.rip_info:
            return self.rip_info.get('offset')
        return None
        
    @property
    def rip_size(self) -> Optional[str]: # Returns only the size part e.g. 0x510
        if self.rip_info:
            return self.rip_info.get('size')
        return None

class StackTraceParser:
    """Parser for kernel stack traces."""
    
    def parse_file(self, file_path: str) -> StackTrace:
        """Parse a stack trace from a file."""
        with open(file_path, 'r') as f:
            content = f.read()
        return self.parse(content)
    
    def _normalize_hex_value(self, val: Optional[str]) -> Optional[str]:
        if val:
            val_lower = val.lower()
            if val_lower.startswith('0x'):
                return '0x' + val_lower[2:]
            return '0x' + val_lower
        return None

    def parse(self, content: str) -> StackTrace:
        """Parse stack trace content."""
        lines = content.split('\n')
        parsed_frames: List[StackFrame] = []
        error_type = "unknown"
        error_message = None
        rip_info: Optional[dict] = None
        
        in_call_trace_block = False
        # Regex for lines in "Call Trace:" block, e.g., "  symbol+offset/size" or "  ? symbol"
        # Captures: 1:symbol_part, 2:offset, 3:size, 4:module
        call_trace_frame_regex = re.compile(
            r"^\s*(\??\s*[\w.:<>-]+)"  # Symbol part (group 1)
            r"(?:\+([0-9a-fA-F]+|0x[0-9a-fA-F]+))?"  # Optional offset (group 2)
            r"(?:/([0-9a-fA-F]+|0x[0-9a-fA-F]+))?"  # Optional size (group 3)
            r"\s*(?:\[([\w.-]+)\])?\s*$"  # Optional module (group 4)
        )
        # Regex for standard frames with address: "[<addr>] symbol+offset/size [module]"
        std_frame_regex = re.compile(
            r"\[<([0-9a-fA-F]+)>\]\s*"  # Address (group 1)
            r"(\??\s*[\w.:<>-]+)"  # Symbol part (group 2)
            r"(?:\+([0-9a-fA-F]+|0x[0-9a-fA-F]+))?"  # Optional offset (group 3)
            r"(?:/([0-9a-fA-F]+|0x[0-9a-fA-F]+))?"  # Optional size (group 4)
            r"\s*(?:\[([\w.-]+)\])?\s*$"  # Optional module (group 5)
        )

        for line_num, original_line in enumerate(lines):
            line = original_line.strip()
            if not line:
                continue

            # Detect error type and message - prioritize first detected
            if error_type == "unknown":
                if "Kernel panic" in line:
                    error_type = "kernel_panic"; error_message = line
                elif "soft lockup" in line:
                    error_type = "softlockup"; error_message = line
                elif "KASAN: use-after-free" in line:
                    error_type = "kasan_uaf"; error_message = line
                elif "KASAN: out-of-bounds" in line:
                    error_type = "kasan_oob"; error_message = line
                elif "hung task" in line:
                    error_type = "hung_task"; error_message = line
                elif "WARNING:" in line:
                    error_type = "warning"; error_message = line
                    # Try to parse RIP from WARNING line: " ... at file:line func+off/size"
                    # Example: WARNING: CPU: 1 PID: 3597 at arch/x86/kvm/lapic.c:3384 kvm_apic_accept_events+0x3ad/0x510
                    warn_rip_match = re.search(
                        r'at\s+([^:]+):(\d+)\s+([^+]+)\+([0-9a-fA-F]+|0x[0-9a-fA-F]+)/([0-9a-fA-F]+|0x[0-9a-fA-F]+)', line)
                    if warn_rip_match:
                        rip_info = {
                            'symbol': warn_rip_match.group(3).strip(),
                            'offset': self._normalize_hex_value(warn_rip_match.group(4)),
                            'size': self._normalize_hex_value(warn_rip_match.group(5)),
                            'file': warn_rip_match.group(1).strip(),
                            'line': int(warn_rip_match.group(2))
                        }

            # Parse explicit RIP line if rip_info not already set or to confirm/augment
            # Example: RIP: 0010:kvm_apic_accept_events+0x3ad/0x510
            explicit_rip_match = re.search(r'RIP:\s*\w*:([^+]+)\+([0-9a-fA-F]+|0x[0-9a-fA-F]+)/([0-9a-fA-F]+|0x[0-9a-fA-F]+)', line)
            if explicit_rip_match:
                symbol = explicit_rip_match.group(1).strip()
                offset = self._normalize_hex_value(explicit_rip_match.group(2))
                size = self._normalize_hex_value(explicit_rip_match.group(3))
                if not rip_info: # If rip_info not set by WARNING line, use this
                    rip_info = {'symbol': symbol, 'offset': offset, 'size': size}
                else: # rip_info was set by WARNING line, ensure all fields are consistent or augmented
                    rip_info['symbol'] = symbol # Explicit RIP symbol is usually more canonical
                    rip_info['offset'] = offset
                    rip_info['size'] = size # Ensure size is also taken from explicit RIP line if present

            # Handle Call Trace block
            if "Call Trace:" in line:
                in_call_trace_block = True
                parsed_frames = [] # Prioritize frames from this block
                continue

            if in_call_trace_block and ("</TASK>" in line or "---[ end trace" in line):
                in_call_trace_block = False
                continue

            if in_call_trace_block:
                # Strip potential "[timestamp][PID]" prefix before matching frame content
                content_part = line
                prefix_match = re.match(r'(?:\[\s*[\d.]+\]\s*\[\s*T\d+\]\s*)?(.*)', line)
                if prefix_match:
                    content_part = prefix_match.group(1).strip()

                match = call_trace_frame_regex.match(content_part)
                if match:
                    symbol_part, offset_val, size_val, module_name = match.groups()

                    if symbol_part.startswith('?') or symbol_part == "<TASK>":
                        continue # Skip ? prefixed symbols and <TASK> marker

                    symbol = symbol_part.strip()
                    offset_norm = self._normalize_hex_value(offset_val)
                    size_norm = self._normalize_hex_value(size_val)

                    offset_str = offset_norm
                    if offset_norm and size_norm and size_norm != '0x0':
                        offset_str = f"{offset_norm}/{size_norm}"

                    parsed_frames.append(StackFrame(
                        address="<trace>", symbol=symbol, offset=offset_str,
                        module=module_name, is_exported=True # is_exported is true if not starting with ?
                    ))
                # else: Line in call trace block didn't match frame format, skip.

            # Standard frame parsing (if not in call trace block and no frames found yet)
            # This is for traces without "Call Trace:" header or other contexts.
            elif not parsed_frames:
                match = std_frame_regex.search(line) # Search because it can be embedded
                if match:
                    addr, symbol_part, offset_val, size_val, module_name = match.groups()

                    if symbol_part.startswith('?'):
                        continue # Skip ? prefixed symbols here too

                    symbol = symbol_part.strip()
                    offset_norm = self._normalize_hex_value(offset_val)
                    size_norm = self._normalize_hex_value(size_val)

                    offset_str = offset_norm
                    if offset_norm and size_norm and size_norm != '0x0':
                       offset_str = f"{offset_norm}/{size_norm}"

                    parsed_frames.append(StackFrame(
                        address=addr, symbol=symbol, offset=offset_str,
                        module=module_name, is_exported=True
                    ))
        
        # If RIP is available and no frames were parsed, create a single frame from RIP info.
        # This is useful for simple warnings where the "at" line is the primary information.
        if rip_info and not parsed_frames:
            offset_val = rip_info.get('offset')
            size_val = rip_info.get('size')
            display_offset_str = offset_val
            if offset_val and size_val and size_val != '0x0':
                display_offset_str = f"{offset_val}/{size_val}"

            parsed_frames.append(StackFrame(
                address=rip_info.get('file', '<RIP>') + (f":{rip_info['line']}" if 'line' in rip_info else ""),
                symbol=rip_info['symbol'],
                offset=display_offset_str,
                file=rip_info.get('file'),
                line=rip_info.get('line'),
                is_exported=True
            ))

        return StackTrace(parsed_frames, error_type, error_message, rip_info)