import os
from typing import Dict, List
import asyncio
from openai import AsyncOpenAI
from dotenv import load_dotenv

load_dotenv()

class StackTraceAnalyzer:
    """AI-powered stack trace analyzer."""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        if not debug:
            self.client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        
    async def analyze(self, stack_trace, code_contexts: Dict[str, str]) -> str:
        """Analyze a stack trace with its code contexts."""
        # Prepare the analysis prompt
        prompt = self._create_analysis_prompt(stack_trace, code_contexts)
        system_message = "You are an expert kernel developer analyzing stack traces."
        
        if self.debug:
            return {
                "system_message": system_message,
                "prompt": prompt,
                "model": "gpt-4o-mini",
                "temperature": 0.7,
                "max_tokens": 1000
            }
        
        # Get AI analysis
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
    
    def _create_analysis_prompt(self, stack_trace, code_contexts: Dict[str, str]) -> str:
        """Create a prompt for the AI analysis."""
        prompt = f"""Analyze the following kernel stack trace and its associated code:

Error Type: {stack_trace.error_type}
Error Message: {stack_trace.error_message}

"""
        # Add RIP information if available
        if stack_trace.rip_frame:
            prompt += f"""Instruction Pointer (RIP):
Symbol: {stack_trace.rip_frame.symbol}
Offset: {stack_trace.rip_frame.offset}
"""
            if stack_trace.rip_symbol in code_contexts:
                prompt += f"""
RIP Symbol Code:
{code_contexts[stack_trace.rip_symbol]}
"""

        prompt += "\nStack Trace:\n"
        for i, frame in enumerate(stack_trace.frames):
            prompt += f"\n{i+1}. {frame.symbol}"
            if frame.offset:
                prompt += f" +{frame.offset}"
            prompt += "\n"
            if frame.symbol in code_contexts and frame.symbol != stack_trace.rip_symbol:  # Skip RIP code as it's already shown
                prompt += f"Code:\n{code_contexts[frame.symbol]}\n"
        
        prompt += """
Please provide:
1. A high-level summary of what this stack trace represents, focusing on the instruction pointer location
2. Analysis of the code at the RIP location and its role in the error
3. The sequence of events that led to this error
4. Potential root causes based on the code analysis
5. Suggestions for debugging or fixing the issue
"""
        return prompt

class MultiTraceAnalyzer:
    """Analyzer for multiple stack traces."""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        if not debug:
            self.analyzer = StackTraceAnalyzer(debug=debug)
        else:
            self.analyzer = StackTraceAnalyzer(debug=True)
        
    async def analyze_traces(self, stack_traces: List[tuple], code_contexts: List[Dict[str, str]]) -> str:
        """Analyze multiple stack traces in parallel."""
        if self.debug:
            tasks = []
            for stack_trace, contexts in zip(stack_traces, code_contexts):
                tasks.append(self.analyzer.analyze(stack_trace, contexts))
            
            # Get individual prompts
            prompts = await asyncio.gather(*tasks)
            
            # Combine prompts
            combined_prompt = self._create_combined_prompt([p["prompt"] for p in prompts])
            system_message = "You are an expert kernel developer analyzing multiple stack traces."
            
            return {
                "system_message": system_message,
                "prompt": combined_prompt,
                "model": "gpt-4o-mini",
                "temperature": 0.7,
                "max_tokens": 1500
            }
            
        tasks = []
        for stack_trace, contexts in zip(stack_traces, code_contexts):
            tasks.append(self.analyzer.analyze(stack_trace, contexts))
        
        # Get individual analyses
        analyses = await asyncio.gather(*tasks)
        
        # Combine analyses
        combined_prompt = self._create_combined_prompt(analyses)
        
        # Get final combined analysis
        response = await self.analyzer.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an expert kernel developer analyzing multiple stack traces."},
                {"role": "user", "content": combined_prompt}
            ],
            temperature=0.7,
            max_tokens=1500
        )
        
        return response.choices[0].message.content
    
    def _create_combined_prompt(self, analyses: List[str]) -> str:
        """Create a prompt for combining multiple analyses."""
        prompt = "Analyze the following multiple stack trace analyses and provide a comprehensive summary:\n\n"
        
        for i, analysis in enumerate(analyses, 1):
            prompt += f"Analysis {i}:\n{analysis}\n\n"
        
        prompt += """
Please provide:
1. Common patterns or themes across the stack traces
2. Potential systemic issues
3. Root cause analysis considering all traces
4. Recommendations for investigation and fixes
"""
        return prompt 