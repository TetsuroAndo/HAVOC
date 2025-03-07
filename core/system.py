"""
Core System for CTF Automator.
Provides the main control flow and basic functionality.
"""
import os
import yaml
import logging
import datetime
from typing import Dict, List, Any, Optional, Union

from core.input_handler import InputHandler
from core.classifier import ChallengeClassifier
from core.output_handler import OutputHandler
from core.flag_validator import FlagValidator
from reports.report_repository import ReportRepository


class CoreSystem:
    """
    Core system that manages the overall CTF challenge analysis process.
    """
    
    def __init__(self, config_path="config/settings.yaml", log_level=logging.INFO):
        """
        Initialize the core system.
        
        Args:
            config_path: Path to the configuration file
            log_level: Logging level (default: INFO)
        """
        self.config = self._load_config(config_path)
        self.logger = self._setup_logger(log_level)
        self.report_repository = ReportRepository(self.config.get("reports", {}).get("reports_dir", "data/reports"))
        self.input_handler = InputHandler(self.logger, self.config)
        self.challenge_classifier = ChallengeClassifier(self.logger, self.config)
        self.flag_validator = FlagValidator(self.logger, self.config)
        self.output_handler = OutputHandler(self.logger, self.config)
        
        self.logger.info("Core system initialized")
    
    def _load_config(self, config_path):
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as file:
                return yaml.safe_load(file)
        except Exception as e:
            print(f"Error loading configuration: {e}")
            return {}
    
    def _setup_logger(self, log_level):
        """Set up the logger for the core system."""
        logger = logging.getLogger("CTFAutomator")
        logger.setLevel(log_level)
        
        # Create handlers
        c_handler = logging.StreamHandler()
        f_handler = logging.FileHandler("ctf_automator.log")
        c_handler.setLevel(log_level)
        f_handler.setLevel(log_level)
        
        # Create formatters and add to handlers
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        c_handler.setFormatter(formatter)
        f_handler.setFormatter(formatter)
        
        # Add handlers to the logger
        logger.addHandler(c_handler)
        logger.addHandler(f_handler)
        
        return logger
    
    def run(self, input_data: Union[str, Dict[str, Any]], challenge_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Run the CTF analysis process.
        
        Args:
            input_data: Input data for the CTF challenge (file path, URL, or text)
            challenge_type: Optional explicit challenge type
            
        Returns:
            Dict containing the analysis results and flag if found
        """
        self.logger.info("Starting CTF analysis process")
        
        # Process input
        processed_input = self.input_handler.process(input_data)
        self.logger.info(f"Input processed: {processed_input['type']}")
        
        # Classify challenge if not explicitly provided
        if not challenge_type:
            challenge_type = self.challenge_classifier.classify(processed_input)
            self.logger.info(f"Challenge classified as: {challenge_type}")
        else:
            self.logger.info(f"Using provided challenge type: {challenge_type}")
        
        # Initialize appropriate diagnostic module based on challenge type
        diagnostic_module = self._get_diagnostic_module(challenge_type)
        if not diagnostic_module:
            self.logger.error(f"No diagnostic module available for challenge type: {challenge_type}")
            return {"error": f"Unsupported challenge type: {challenge_type}"}
        
        # Run diagnostic
        self.logger.info(f"Running diagnostic for {challenge_type} challenge")
        diagnostic_report = diagnostic_module.diagnose(processed_input)
        self.report_repository.save_report(diagnostic_report)
        self.logger.info(f"Diagnostic completed: {diagnostic_report['id']}")
        
        # Initialize analyzer module
        analyzer_module = self._get_analyzer_module(challenge_type)
        if not analyzer_module:
            self.logger.error(f"No analyzer module available for challenge type: {challenge_type}")
            return {"error": f"Unsupported analyzer for challenge type: {challenge_type}"}
        
        # Run analysis
        self.logger.info(f"Running analysis for {challenge_type} challenge")
        analysis_report = analyzer_module.analyze(diagnostic_report)
        self.report_repository.save_report(analysis_report)
        self.logger.info(f"Analysis completed: {analysis_report['id']}")
        
        # Initialize LLM engine and agent controller
        from llm_engine.engine import LLMEngine
        from agent.agent_controller import AgentController
        
        llm_engine = LLMEngine(self.config)
        agent_controller = AgentController(llm_engine, self.config)
        
        # Get agent action based on diagnostic and analysis reports
        self.logger.info("Consulting LLM agent for exploitation strategy")
        agent_action = agent_controller.determine_action(diagnostic_report, analysis_report)
        
        # Initialize exploiter module
        exploiter_module = self._get_exploiter_module(challenge_type)
        if not exploiter_module:
            self.logger.error(f"No exploiter module available for challenge type: {challenge_type}")
            return {"error": f"Unsupported exploiter for challenge type: {challenge_type}"}
        
        # Run exploit with agent guidance
        self.logger.info(f"Running exploitation for {challenge_type} challenge")
        exploit_result = agent_controller.run_module(exploiter_module, agent_action, analysis_report)
        self.report_repository.save_report(exploit_result)
        self.logger.info(f"Exploitation completed: {exploit_result['id']}")
        
        # Extract and validate flag
        flag = exploit_result.get("content", {}).get("flag")
        if flag:
            is_valid = self.flag_validator.validate(flag)
            self.logger.info(f"Flag validation: {is_valid}")
            
            # Prepare output
            result = {
                "challenge_type": challenge_type,
                "flag": flag,
                "is_valid_flag": is_valid,
                "reports": {
                    "diagnostic": diagnostic_report["id"],
                    "analysis": analysis_report["id"],
                    "exploit": exploit_result["id"]
                }
            }
            
            # Format and return output
            return self.output_handler.format_output(result)
        else:
            self.logger.warning("No flag found in exploit result")
            return {"error": "No flag found", "reports": {
                "diagnostic": diagnostic_report["id"],
                "analysis": analysis_report["id"],
                "exploit": exploit_result["id"]
            }}
    
    def _get_diagnostic_module(self, challenge_type):
        """Get the appropriate diagnostic module based on challenge type."""
        try:
            if challenge_type == "binary":
                from diagnostic.binary.binary_diagnostic import BinaryDiagnostic
                return BinaryDiagnostic(self.logger, self.config)
            elif challenge_type == "web":
                from diagnostic.web.web_diagnostic import WebDiagnostic
                return WebDiagnostic(self.logger, self.config)
            elif challenge_type == "crypto":
                from diagnostic.crypto.crypto_diagnostic import CryptoDiagnostic
                return CryptoDiagnostic(self.logger, self.config)
            elif challenge_type == "forensic":
                from diagnostic.forensic.forensic_diagnostic import ForensicDiagnostic
                return ForensicDiagnostic(self.logger, self.config)
            elif challenge_type == "misc":
                from diagnostic.misc.misc_diagnostic import MiscDiagnostic
                return MiscDiagnostic(self.logger, self.config)
            else:
                self.logger.error(f"Unknown challenge type: {challenge_type}")
                return None
        except ImportError as e:
            self.logger.error(f"Failed to import diagnostic module for {challenge_type}: {e}")
            return None
    
    def _get_analyzer_module(self, challenge_type):
        """Get the appropriate analyzer module based on challenge type."""
        try:
            if challenge_type == "binary":
                from analyzer.binary.binary_analyzer import BinaryAnalyzer
                return BinaryAnalyzer(self.logger, self.config)
            elif challenge_type == "web":
                from analyzer.web.web_analyzer import WebAnalyzer
                return WebAnalyzer(self.logger, self.config)
            elif challenge_type == "crypto":
                from analyzer.crypto.crypto_analyzer import CryptoAnalyzer
                return CryptoAnalyzer(self.logger, self.config)
            elif challenge_type == "forensic":
                from analyzer.forensic.forensic_analyzer import ForensicAnalyzer
                return ForensicAnalyzer(self.logger, self.config)
            elif challenge_type == "misc":
                from analyzer.misc.misc_analyzer import MiscAnalyzer
                return MiscAnalyzer(self.logger, self.config)
            else:
                self.logger.error(f"Unknown challenge type: {challenge_type}")
                return None
        except ImportError as e:
            self.logger.error(f"Failed to import analyzer module for {challenge_type}: {e}")
            return None
    
    def _get_exploiter_module(self, challenge_type):
        """Get the appropriate exploiter module based on challenge type."""
        try:
            if challenge_type == "binary":
                from exploiter.binary.binary_exploiter import BinaryExploiter
                return BinaryExploiter(self.logger, self.config)
            elif challenge_type == "web":
                from exploiter.web.web_exploiter import WebExploiter
                return WebExploiter(self.logger, self.config)
            elif challenge_type == "crypto":
                from exploiter.crypto.crypto_solver import CryptoSolver
                return CryptoSolver(self.logger, self.config)
            elif challenge_type == "forensic":
                from exploiter.forensic.forensic_extractor import ForensicExtractor
                return ForensicExtractor(self.logger, self.config)
            elif challenge_type == "misc":
                from exploiter.misc.misc_solver import MiscSolver
                return MiscSolver(self.logger, self.config)
            else:
                self.logger.error(f"Unknown challenge type: {challenge_type}")
                return None
        except ImportError as e:
            self.logger.error(f"Failed to import exploiter module for {challenge_type}: {e}")
            return None
