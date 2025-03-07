from setuptools import setup, find_packages

setup(
    name="ctf-automator",
    version="0.1.0",
    description="Automated system for analyzing and solving CTF challenges",
    author="CTF Automator Team",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        "pyyaml",
        "requests",
        "pwntools",
        "pycryptodome",
        "beautifulsoup4",
        "angr",
        "r2pipe",
        "langchain",
        "openai",
        "anthropic",
        "google-generativeai",
    ],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
