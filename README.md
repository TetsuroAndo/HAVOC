# HAVOC

HAVOC is an advanced system for automatically analyzing and solving Capture The Flag (CTF) challenges. It uses a combination of specialized diagnostic tools, analyzers, exploiters, and LLM-powered agents to identify vulnerabilities and extract flags.

## Features

- **Multi-category Support**: Handles binary, web, crypto, forensic, and misc challenges
- **Automated Analysis**: Performs initial diagnostics and in-depth analysis
- **Intelligent Exploitation**: Automatically generates and executes exploits
- **LLM Integration**: Uses ChatGPT, Claude, and Gemini for advanced reasoning
- **Modular Architecture**: Easily extensible with new tools and techniques

## Architecture

The system follows a layered architecture:

1. **Diagnostic Layer**: Low-cost initial analysis
2. **Analysis Layer**: In-depth vulnerability assessment
3. **Exploitation Layer**: Automated flag extraction
4. **Agent Layer**: LLM-powered decision making

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/havoc.git
cd havoc

# Install dependencies
pip install -r requirements.txt

# Set up environment
./scripts/setup_environment.sh
```

## Usage

```bash
# Basic usage
python scripts/run_havoc.py --input path/to/challenge

# Specify challenge type
python scripts/run_havoc.py --input path/to/challenge --type binary

# Use specific LLM provider
python scripts/run_havoc.py --input path/to/challenge --llm-provider openai
```

## Configuration

Edit the configuration files in the `config/` directory to customize the behavior of the system:

- `settings.yaml`: General settings
- `llm_config.yaml`: LLM provider settings
- `modules_config/`: Category-specific settings
