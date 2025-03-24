import os
from typing import Dict, Optional
from openai import AsyncOpenAI
from dotenv import load_dotenv

load_dotenv()

class ContextAnalyzer:
    """Analyzer for different kernel error contexts."""
    
    def __init__(self, context_type: str, debug: bool = False):
        self.context_type = context_type
        self.debug = debug
        if not debug:
            self.client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        
    async def analyze(self, stack_analysis: str) -> str:
        """Analyze the stack trace in the context of the error type."""
        prompt = self._create_context_prompt(stack_analysis)
        system_message = self._get_system_prompt()
        
        if self.debug:
            return {
                "system_message": system_message,
                "prompt": prompt,
                "model": "gpt-4o-mini",
                "temperature": 0.7,
                "max_tokens": 1000
            }
        
        response = await self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1000
        )
        
        return response.choices[0].message.content
    
    def _get_system_prompt(self) -> str:
        """Get the appropriate system prompt based on context type."""
        prompts = {
            "kernel_panic": "You are an expert in analyzing kernel panics and system crashes.",
            "softlockup": "You are an expert in analyzing soft lockups and system hangs.",
            "kasan_uaf": "You are an expert in analyzing use-after-free bugs and memory corruption.",
            "kasan_oob": "You are an expert in analyzing out-of-bounds access bugs.",
            "hung_task": "You are an expert in analyzing hung tasks and process deadlocks."
        }
        return prompts.get(self.context_type, "You are an expert kernel developer.")
    
    def _create_context_prompt(self, stack_analysis: str) -> str:
        """Create a context-specific analysis prompt."""
        context_prompts = {
            "kernel_panic": """
Analyze this kernel panic stack trace and provide:
1. The immediate cause of the panic
2. The sequence of events that led to the panic
3. Potential system state issues
4. Recommendations for preventing similar panics
""",
            "softlockup": """
Analyze this soft lockup stack trace and provide:
1. The task or subsystem that is locked up
2. Potential deadlock or blocking conditions
3. System resource issues
4. Recommendations for preventing soft lockups
""",
            "kasan_uaf": """
Analyze this use-after-free stack trace and provide:
1. The object that was freed and then accessed
2. The timing of the free and use operations
3. Potential race conditions
4. Recommendations for fixing the memory management
""",
            "kasan_oob": """
Analyze this out-of-bounds access stack trace and provide:
1. The buffer or array being accessed
2. The nature of the out-of-bounds access
3. Potential buffer overflow conditions
4. Recommendations for fixing the bounds checking
""",
            "hung_task": """
Analyze this hung task stack trace and provide:
1. The task that is hung
2. The blocking condition
3. Potential deadlock scenarios
4. Recommendations for preventing task hangs
"""
        }
        
        prompt = context_prompts.get(self.context_type, "Analyze this stack trace and provide a detailed analysis.")
        
        return f"""Stack Trace Analysis:
{stack_analysis}

{prompt}""" 