"""
Challenge Classifier for CTF Automator.
Classifies CTF challenges into appropriate categories.
"""
import os
import re
import logging
import subprocess
from typing import Dict, Any, List, Optional


class ChallengeClassifier:
    """
    Classifies CTF challenges into appropriate categories.
    """
    
    def __init__(self, logger, config):
        """
        Initialize the challenge classifier.
        
        Args:
            logger: Logger instance
            config: Configuration dictionary
        """
        self.logger = logger
        self.config = config
        self.confidence_threshold = config.get("classifier", {}).get("confidence_threshold", 0.7)
        self.use_llm = config.get("classifier", {}).get("use_llm_for_classification", True)
    
    def classify(self, processed_input: Dict[str, Any]) -> str:
        """
        Classify the challenge based on processed input.
        
        Args:
            processed_input: Processed input data
            
        Returns:
            Challenge type (binary, web, crypto, forensic, misc)
        """
        input_type = processed_input.get("type")
        
        # Initial classification based on input type
        if input_type == "file":
            classification, confidence = self._classify_file(processed_input)
        elif input_type == "url":
            classification, confidence = "web", 0.9  # URLs are typically web challenges
        elif input_type == "text":
            classification, confidence = self._classify_text(processed_input)
        else:
            self.logger.error(f"Unknown input type: {input_type}")
            return "unknown"
        
        self.logger.info(f"Initial classification: {classification} (confidence: {confidence:.2f})")
        
        # If confidence is below threshold and LLM is enabled, use LLM for classification
        if confidence < self.confidence_threshold and self.use_llm:
            llm_classification = self._classify_with_llm(processed_input)
            if llm_classification:
                self.logger.info(f"LLM classification: {llm_classification}")
                return llm_classification
        
        return classification
    
    def _classify_file(self, processed_input: Dict[str, Any]) -> tuple:
        """
        Classify a file-based challenge.
        
        Args:
            processed_input: Processed input data
            
        Returns:
            Tuple of (classification, confidence)
        """
        file_path = processed_input.get("path")
        file_type = processed_input.get("file_type", "unknown")
        
        # Basic classification based on file type
        if file_type in ["elf", "exe", "dll", "so", "dylib"]:
            return "binary", 0.9
        elif file_type in ["pcap", "pcapng", "cap"]:
            return "network", 0.9
        elif file_type in ["jpg", "png", "gif", "bmp", "wav", "mp3", "pdf"]:
            return "forensic", 0.8
        elif file_type in ["zip", "tar", "gz", "rar"]:
            # For archives, check the contents
            extracted_path = processed_input.get("extracted_path")
            if extracted_path:
                return self._classify_directory(extracted_path)
            else:
                return "misc", 0.5
        elif file_type in ["py", "js", "php", "html", "css"]:
            return "web", 0.7
        elif file_type in ["txt", "md"]:
            # Further analysis needed for text files
            return self._analyze_text_file(file_path)
        else:
            # Run file command for better identification
            file_output = self._run_file_command(file_path)
            return self._classify_from_file_output(file_output)
    
    def _classify_text(self, processed_input: Dict[str, Any]) -> tuple:
        """
        Classify a text-based challenge.
        
        Args:
            processed_input: Processed input data
            
        Returns:
            Tuple of (classification, confidence)
        """
        content = processed_input.get("content", "")
        
        # Check for common crypto patterns
        crypto_patterns = [
            r"base64", r"md5", r"sha", r"aes", r"rsa", r"des", r"cipher", 
            r"encrypt", r"decrypt", r"key", r"hash", r"[a-f0-9]{32,}", 
            r"[a-zA-Z0-9+/]{4,}={0,2}"
        ]
        
        web_patterns = [
            r"http", r"html", r"javascript", r"php", r"sql", r"injection",
            r"xss", r"csrf", r"cookie", r"session", r"login", r"password",
            r"admin", r"<script", r"<html", r"SELECT.*FROM"
        ]
        
        binary_patterns = [
            r"buffer overflow", r"format string", r"shellcode", r"exploit",
            r"rop", r"ret2libc", r"stack", r"heap", r"bof", r"0x[0-9a-f]+",
            r"segmentation fault", r"core dump", r"assembly", r"disassembly"
        ]
        
        forensic_patterns = [
            r"file header", r"magic bytes", r"metadata", r"exif", r"hidden",
            r"steganography", r"stego", r"embedded", r"extract", r"analyze"
        ]
        
        # Count matches for each category
        crypto_count = sum(1 for pattern in crypto_patterns if re.search(pattern, content, re.IGNORECASE))
        web_count = sum(1 for pattern in web_patterns if re.search(pattern, content, re.IGNORECASE))
        binary_count = sum(1 for pattern in binary_patterns if re.search(pattern, content, re.IGNORECASE))
        forensic_count = sum(1 for pattern in forensic_patterns if re.search(pattern, content, re.IGNORECASE))
        
        # Determine the category with the most matches
        counts = {
            "crypto": crypto_count,
            "web": web_count,
            "binary": binary_count,
            "forensic": forensic_count
        }
        
        max_category = max(counts, key=counts.get)
        max_count = counts[max_category]
        
        # Calculate confidence based on the difference between the highest and second highest
        sorted_counts = sorted(counts.values(), reverse=True)
        if len(sorted_counts) > 1 and sorted_counts[0] > 0:
            confidence = min(0.5 + (sorted_counts[0] - sorted_counts[1]) / sorted_counts[0] * 0.5, 0.9)
        elif sorted_counts[0] > 0:
            confidence = 0.7
        else:
            # No matches found
            max_category = "misc"
            confidence = 0.5
        
        return max_category, confidence
    
    def _analyze_text_file(self, file_path: str) -> tuple:
        """
        Analyze a text file to determine challenge type.
        
        Args:
            file_path: Path to the text file
            
        Returns:
            Tuple of (classification, confidence)
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return self._classify_text({"content": content})
        except Exception as e:
            self.logger.error(f"Error analyzing text file: {e}")
            return "misc", 0.5
    
    def _run_file_command(self, file_path: str) -> str:
        """
        Run the 'file' command on a file to get more information.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Output of the file command
        """
        try:
            result = subprocess.run(['file', file_path], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            self.logger.error(f"Error running file command: {e}")
            return ""
    
    def _classify_from_file_output(self, file_output: str) -> tuple:
        """
        Classify a file based on the output of the 'file' command.
        
        Args:
            file_output: Output of the file command
            
        Returns:
            Tuple of (classification, confidence)
        """
        file_output = file_output.lower()
        
        if any(term in file_output for term in ["elf", "executable", "binary"]):
            return "binary", 0.8
        elif any(term in file_output for term in ["image", "jpeg", "png", "gif"]):
            return "forensic", 0.7
        elif any(term in file_output for term in ["pcap", "capture"]):
            return "network", 0.8
        elif any(term in file_output for term in ["text", "ascii"]):
            if any(term in file_output for term in ["html", "php", "javascript"]):
                return "web", 0.7
            else:
                return "misc", 0.6
        else:
            return "misc", 0.5
    
    def _classify_directory(self, directory_path: str) -> tuple:
        """
        Classify a directory based on its contents.
        
        Args:
            directory_path: Path to the directory
            
        Returns:
            Tuple of (classification, confidence)
        """
        # Count files by type
        file_types = {"binary": 0, "web": 0, "crypto": 0, "forensic": 0, "misc": 0}
        
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                _, ext = os.path.splitext(file)
                ext = ext.lower()[1:] if ext else ""
                
                if ext in ["elf", "exe", "dll", "so", "dylib"]:
                    file_types["binary"] += 1
                elif ext in ["html", "php", "js", "css"]:
                    file_types["web"] += 1
                elif ext in ["jpg", "png", "gif", "wav", "mp3", "pdf"]:
                    file_types["forensic"] += 1
                elif ext in ["py", "txt", "md"]:
                    # Check content for these files
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(1024)  # Read first 1KB
                        
                        if any(pattern in content.lower() for pattern in ["encrypt", "decrypt", "cipher", "hash"]):
                            file_types["crypto"] += 1
                        elif any(pattern in content.lower() for pattern in ["http", "html", "sql", "injection"]):
                            file_types["web"] += 1
                        else:
                            file_types["misc"] += 1
                    except:
                        file_types["misc"] += 1
                else:
                    file_types["misc"] += 1
        
        # Determine the category with the most files
        max_category = max(file_types, key=file_types.get)
        max_count = file_types[max_category]
        
        # Calculate confidence
        total_files = sum(file_types.values())
        if total_files > 0:
            confidence = min(0.5 + (max_count / total_files) * 0.5, 0.9)
        else:
            confidence = 0.5
            max_category = "misc"
        
        return max_category, confidence
    
    def _classify_with_llm(self, processed_input: Dict[str, Any]) -> Optional[str]:
        """
        Use LLM to classify the challenge.
        
        Args:
            processed_input: Processed input data
            
        Returns:
            Classification from LLM or None if not available
        """
        try:
            from llm_engine.engine import LLMEngine
            
            llm_engine = LLMEngine(self.config)
            
            # Prepare prompt for LLM
            prompt = self._prepare_classification_prompt(processed_input)
            
            # Get response from LLM
            response = llm_engine.get_completion(prompt)
            
            # Parse response to extract classification
            classification = self._parse_llm_classification(response)
            
            return classification
        except Exception as e:
            self.logger.error(f"Error using LLM for classification: {e}")
            return None
    
    def _prepare_classification_prompt(self, processed_input: Dict[str, Any]) -> str:
        """
        Prepare a prompt for LLM classification.
        
        Args:
            processed_input: Processed input data
            
        Returns:
            Prompt for LLM
        """
        input_type = processed_input.get("type")
        
        prompt = "You are an expert in CTF (Capture The Flag) challenges. "
        prompt += "Based on the following information, classify this challenge into one of these categories: "
        prompt += "binary, web, crypto, forensic, network, or misc.\n\n"
        
        if input_type == "file":
            prompt += f"File type: {processed_input.get('file_type', 'unknown')}\n"
            prompt += f"File name: {processed_input.get('file_name', 'unknown')}\n"
            prompt += f"File size: {processed_input.get('size', 'unknown')} bytes\n"
            
            # Add file content preview if it's a text file
            if processed_input.get('file_type') in ['txt', 'md', 'py', 'js', 'html', 'css', 'php']:
                try:
                    with open(processed_input.get('path'), 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1000)  # First 1000 characters
                    prompt += f"\nFile content preview:\n{content}\n"
                except:
                    pass
                
        elif input_type == "url":
            prompt += f"URL: {processed_input.get('url', 'unknown')}\n"
            prompt += f"Content type: {processed_input.get('content_type', 'unknown')}\n"
            
        elif input_type == "text":
            prompt += f"Text content:\n{processed_input.get('content', '')[:1000]}\n"
        
        prompt += "\nRespond with only the category name (binary, web, crypto, forensic, network, or misc)."
        
        return prompt
    
    def _parse_llm_classification(self, response: str) -> Optional[str]:
        """
        Parse the LLM response to extract the classification.
        
        Args:
            response: LLM response
            
        Returns:
            Extracted classification or None if parsing fails
        """
        # Clean and lowercase the response
        response = response.strip().lower()
        
        # Valid categories
        valid_categories = ["binary", "web", "crypto", "forensic", "network", "misc"]
        
        # Check if the response is a valid category
        for category in valid_categories:
            if category in response:
                return category
        
        # If no valid category found, return None
        return None
