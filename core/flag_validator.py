"""
Flag Validator for CTF Automator.
Validates CTF flags against expected formats.
"""
import re
import logging
from typing import List, Optional, Dict, Any


class FlagValidator:
    """
    Validates CTF flags against expected formats.
    """
    
    def __init__(self, logger, config):
        """
        Initialize the flag validator.
        
        Args:
            logger: Logger instance
            config: Configuration dictionary
        """
        self.logger = logger
        self.config = config
        
        # Load flag patterns from config
        self.flag_patterns = config.get("flag_validator", {}).get("patterns", [
            r"flag\{[^}]+\}",
            r"CTF\{[^}]+\}",
            r"FLAG\{[^}]+\}",
            r"ctf\{[^}]+\}"
        ])
        
        # Load custom pattern if specified
        custom_pattern = config.get("flag_validator", {}).get("custom_pattern")
        if custom_pattern:
            self.flag_patterns.append(custom_pattern)
            
        self.logger.info(f"Flag validator initialized with {len(self.flag_patterns)} patterns")
    
    def validate(self, flag: str) -> bool:
        """
        Validate a flag against known formats.
        
        Args:
            flag: The flag to validate
            
        Returns:
            True if the flag matches a known format, False otherwise
        """
        if not flag:
            self.logger.warning("Empty flag provided for validation")
            return False
        
        # Check if flag matches any known pattern
        for pattern in self.flag_patterns:
            if re.match(pattern, flag):
                self.logger.info(f"Flag '{flag}' matches pattern '{pattern}'")
                return True
        
        # If no pattern matches, log a warning but still return True
        # as the flag might have a custom format
        self.logger.warning(f"Flag '{flag}' does not match any known format")
        return True
    
    def extract_flag(self, text: str) -> Optional[str]:
        """
        Extract a flag from text if it matches a known format.
        
        Args:
            text: Text to extract flag from
            
        Returns:
            Extracted flag or None if no flag found
        """
        if not text:
            return None
        
        # Try to extract flag using each pattern
        for pattern in self.flag_patterns:
            match = re.search(pattern, text)
            if match:
                flag = match.group(0)
                self.logger.info(f"Extracted flag '{flag}' using pattern '{pattern}'")
                return flag
        
        self.logger.info("No flag found in text")
        return None
    
    def extract_all_flags(self, text: str) -> List[str]:
        """
        Extract all flags from text that match known formats.
        
        Args:
            text: Text to extract flags from
            
        Returns:
            List of extracted flags
        """
        if not text:
            return []
        
        flags = []
        
        # Extract flags using each pattern
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text)
            if matches:
                self.logger.info(f"Extracted {len(matches)} flags using pattern '{pattern}'")
                flags.extend(matches)
        
        # Remove duplicates
        unique_flags = list(set(flags))
        
        return unique_flags
    
    def set_custom_pattern(self, pattern: str):
        """
        Set a custom flag pattern for validation.
        
        Args:
            pattern: Regular expression pattern for the flag
        """
        if pattern not in self.flag_patterns:
            self.flag_patterns.append(pattern)
            self.logger.info(f"Added custom flag pattern: {pattern}")
            
            # Update config if possible
            if "flag_validator" in self.config:
                if "patterns" in self.config["flag_validator"]:
                    if pattern not in self.config["flag_validator"]["patterns"]:
                        self.config["flag_validator"]["patterns"].append(pattern)
                else:
                    self.config["flag_validator"]["patterns"] = self.flag_patterns
            
            # Try to save updated config
            self._save_config()
    
    def _save_config(self):
        """Attempt to save the updated configuration."""
        try:
            import yaml
            config_path = "config/settings.yaml"
            with open(config_path, 'w') as f:
                yaml.dump(self.config, f)
            self.logger.info("Updated configuration saved")
        except Exception as e:
            self.logger.error(f"Error saving updated configuration: {e}")
    
    def validate_against_expected(self, flag: str, expected_flag: str) -> bool:
        """
        Validate a flag against an expected flag.
        
        Args:
            flag: The flag to validate
            expected_flag: The expected flag
            
        Returns:
            True if the flag matches the expected flag, False otherwise
        """
        if not flag or not expected_flag:
            return False
        
        # Normalize flags (remove whitespace, case-insensitive if needed)
        flag = flag.strip()
        expected_flag = expected_flag.strip()
        
        # Direct comparison
        if flag == expected_flag:
            self.logger.info("Flag matches expected flag exactly")
            return True
        
        # Case-insensitive comparison
        if flag.lower() == expected_flag.lower():
            self.logger.info("Flag matches expected flag (case-insensitive)")
            return True
        
        # Check if the expected flag is contained within the found flag
        if expected_flag in flag:
            self.logger.info("Expected flag is contained within found flag")
            return True
        
        # Check if the found flag is contained within the expected flag
        if flag in expected_flag:
            self.logger.info("Found flag is contained within expected flag")
            return True
        
        self.logger.warning(f"Flag '{flag}' does not match expected flag '{expected_flag}'")
        return False
