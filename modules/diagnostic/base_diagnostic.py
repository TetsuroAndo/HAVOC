"""
Base Diagnostic Module for CTF Automator.
Provides the foundation for all diagnostic modules.
"""
import os
import uuid
import logging
import datetime
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Union


class BaseDiagnostic(ABC):
    """
    Base class for all diagnostic modules.
    
    Diagnostic modules are responsible for gathering initial information about
    a challenge and providing insights for further analysis.
    """
    
    def __init__(self, logger, config):
        """
        Initialize the base diagnostic module.
        
        Args:
            logger: Logger instance
            config: Configuration dictionary
        """
        self.logger = logger
        self.config = config
        self.report_id = None
        self.diagnostic_type = "base"  # Override in subclasses
        
        # Initialize report data structure
        self.report = {
            "id": None,
            "type": self.diagnostic_type,
            "timestamp": None,
            "metadata": {},
            "content": {},
            "recommendations": []
        }
    
    @abstractmethod
    def diagnose(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform diagnostic analysis on the input data.
        
        Args:
            input_data: Processed input data
            
        Returns:
            Diagnostic report
        """
        pass
    
    def create_report(self, content: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None,
                     recommendations: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Create a diagnostic report.
        
        Args:
            content: Content of the report
            metadata: Metadata for the report
            recommendations: List of recommendations based on the diagnostic
            
        Returns:
            Complete diagnostic report
        """
        # Generate a unique report ID
        self.report_id = str(uuid.uuid4())
        
        # Update report with provided data
        self.report["id"] = self.report_id
        self.report["timestamp"] = datetime.datetime.now().isoformat()
        self.report["content"] = content
        
        if metadata:
            self.report["metadata"] = metadata
        
        if recommendations:
            self.report["recommendations"] = recommendations
        
        # Log report creation
        self.logger.info(f"Created diagnostic report {self.report_id} of type {self.diagnostic_type}")
        
        # Save report to file
        self._save_report()
        
        return self.report
    
    def _save_report(self) -> str:
        """
        Save the report to a file.
        
        Returns:
            Path to the saved report file
        """
        try:
            import json
            
            # Create reports directory if it doesn't exist
            reports_dir = os.path.join("data", "reports", "diagnostic")
            os.makedirs(reports_dir, exist_ok=True)
            
            # Generate filename based on report ID
            filename = f"{self.diagnostic_type}_{self.report_id}.json"
            file_path = os.path.join(reports_dir, filename)
            
            # Write report to file
            with open(file_path, 'w') as f:
                json.dump(self.report, f, indent=2)
            
            self.logger.info(f"Saved diagnostic report to {file_path}")
            return file_path
        
        except Exception as e:
            self.logger.error(f"Error saving diagnostic report: {e}")
            return ""
    
    def get_report(self) -> Dict[str, Any]:
        """
        Get the current diagnostic report.
        
        Returns:
            Current diagnostic report
        """
        return self.report
    
    def add_recommendation(self, action: str, priority: str, focus: str = ""):
        """
        Add a recommendation to the report.
        
        Args:
            action: Recommended action
            priority: Priority of the recommendation (high, medium, low)
            focus: Specific focus area for the action
        """
        recommendation = {
            "action": action,
            "priority": priority,
            "focus": focus
        }
        
        self.report["recommendations"].append(recommendation)
    
    def load_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """
        Load a report from file.
        
        Args:
            report_id: ID of the report to load
            
        Returns:
            Loaded report or None if not found
        """
        try:
            import json
            
            # Check all diagnostic report files
            reports_dir = os.path.join("data", "reports", "diagnostic")
            if not os.path.exists(reports_dir):
                self.logger.warning(f"Reports directory {reports_dir} does not exist")
                return None
            
            # Look for file with matching report ID
            for filename in os.listdir(reports_dir):
                if report_id in filename and filename.endswith(".json"):
                    file_path = os.path.join(reports_dir, filename)
                    
                    with open(file_path, 'r') as f:
                        report = json.load(f)
                    
                    self.logger.info(f"Loaded diagnostic report from {file_path}")
                    return report
            
            self.logger.warning(f"No diagnostic report found with ID {report_id}")
            return None
        
        except Exception as e:
            self.logger.error(f"Error loading diagnostic report: {e}")
            return None


class DiagnosticFactory:
    """
    Factory class for creating diagnostic modules.
    """
    
    @staticmethod
    def create_diagnostic(diagnostic_type: str, logger, config) -> Optional[BaseDiagnostic]:
        """
        Create a diagnostic module of the specified type.
        
        Args:
            diagnostic_type: Type of diagnostic module to create
            logger: Logger instance
            config: Configuration dictionary
            
        Returns:
            Diagnostic module instance or None if type is not supported
        """
        try:
            if diagnostic_type == "binary":
                from diagnostic.binary.binary_diagnostic import BinaryDiagnostic
                return BinaryDiagnostic(logger, config)
            
            elif diagnostic_type == "web":
                from diagnostic.web.web_diagnostic import WebDiagnostic
                return WebDiagnostic(logger, config)
            
            elif diagnostic_type == "crypto":
                from diagnostic.crypto.crypto_diagnostic import CryptoDiagnostic
                return CryptoDiagnostic(logger, config)
            
            elif diagnostic_type == "forensic":
                from diagnostic.forensic.forensic_diagnostic import ForensicDiagnostic
                return ForensicDiagnostic(logger, config)
            
            elif diagnostic_type == "network":
                from diagnostic.network.network_diagnostic import NetworkDiagnostic
                return NetworkDiagnostic(logger, config)
            
            elif diagnostic_type == "misc":
                from diagnostic.misc.misc_diagnostic import MiscDiagnostic
                return MiscDiagnostic(logger, config)
            
            else:
                logger.error(f"Unsupported diagnostic type: {diagnostic_type}")
                return None
                
        except ImportError as e:
            logger.error(f"Error importing diagnostic module: {e}")
            return None
        except Exception as e:
            logger.error(f"Error creating diagnostic module: {e}")
            return None
