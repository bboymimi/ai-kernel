# Kernel Stack Trace Analyzer

A powerful tool for analyzing kernel stack traces using AI to help developers understand kernel issues and crashes.

## Features

- Parse kernel stack traces from various sources
- Extract source code for each symbol in the call trace
- AI-powered analysis of stack traces
- Support for multiple stack traces and parallel analysis
- Context-aware analysis for different kernel error types:
  - Kernel Panic
  - Softlockup
  - KASAN issues (UAF, OOB)
  - Hung Tasks
- Root cause analysis and summarization

## Installation

1. Clone the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```
3. Set up your OpenAI API key in a `.env` file:
```
OPENAI_API_KEY=your_api_key_here
```
or
```bash
export OPENAI_API_KEY=your_api_key_here
```

## Usage

1. Prepare the linux kernel source code and build the cscope database.
```bash
cscope -Rbq
```
2. Run the analyzer:
```bash
python -m kernel_stack_analyzer --input panic.txt --context kernel_panic --kernel-src ~/linux-kernel-source/
```
or you can run with debug mode to get the prompt for other LLM models:
```bash
python -m kernel_stack_analyzer --input panic.txt --context kernel_panic --kernel-src ~/linux-kernel-source/ --debug
```

## Project Structure

- `kernel_stack_analyzer/`
  - `parser/` - Stack trace parsing modules
  - `code_extractor/` - Source code extraction for symbols
  - `ai_agents/` - AI analysis modules
  - `context/` - Context-specific analyzers
  - `utils/` - Utility functions
  - `main.py` - Main entry point 