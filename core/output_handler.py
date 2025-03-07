"""
Output Handler for CTF Automator.
Handles formatting and displaying output to the user.
"""
import os
import json
import logging
import datetime
from typing import Dict, Any, Optional, List, Union


class OutputHandler:
    """
    Handles formatting and displaying output to the user.
    """
    
    def __init__(self, logger, config):
        """
        Initialize the output handler.
        
        Args:
            logger: Logger instance
            config: Configuration dictionary
        """
        self.logger = logger
        self.config = config
        self.output_format = config.get("reports", {}).get("format", "json")
        
        # Initialize formatters
        self.formatters = {
            "json": self._format_json,
            "text": self._format_text,
            "markdown": self._format_markdown
        }
    
    def format_output(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format the result for output.
        
        Args:
            result: Result data to format
            
        Returns:
            Formatted output
        """
        # Add timestamp to the result
        result["timestamp"] = datetime.datetime.now().isoformat()
        
        # Add a summary if flag was found
        if "flag" in result and result.get("is_valid_flag", False):
            result["summary"] = f"Flag found: {result['flag']}"
        elif "error" in result:
            result["summary"] = f"Error: {result['error']}"
        else:
            result["summary"] = "Analysis completed, but no flag was found."
        
        return result
    
    def display(self, output: Dict[str, Any], format_type: Optional[str] = None):
        """
        Display the output to the user.
        
        Args:
            output: Output data to display
            format_type: Format type (json, text, markdown)
        """
        # Use specified format or default
        format_type = format_type or self.output_format
        
        # Get formatter function
        formatter = self.formatters.get(format_type, self._format_text)
        
        # Format and display
        formatted_output = formatter(output)
        print(formatted_output)
        
        # Log the output
        self.logger.info(f"Output displayed in {format_type} format")
    
    def save_output(self, output: Dict[str, Any], file_path: Optional[str] = None, 
                   format_type: Optional[str] = None):
        """
        Save the output to a file.
        
        Args:
            output: Output data to save
            file_path: Path to save the output to
            format_type: Format type (json, text, markdown)
        """
        # Use specified format or default
        format_type = format_type or self.output_format
        
        # Generate file path if not provided
        if not file_path:
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            file_path = f"data/reports/results/result_{timestamp}.{format_type}"
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # Get formatter function
        formatter = self.formatters.get(format_type, self._format_text)
        
        # Format and save
        formatted_output = formatter(output)
        with open(file_path, 'w') as f:
            f.write(formatted_output)
        
        self.logger.info(f"Output saved to {file_path} in {format_type} format")
        return file_path
    
    def _format_json(self, output: Dict[str, Any]) -> str:
        """Format output as JSON."""
        return json.dumps(output, indent=2)
    
    def _format_text(self, output: Dict[str, Any]) -> str:
        """Format output as plain text."""
        lines = []
        
        # Add summary
        if "summary" in output:
            lines.append(f"Summary: {output['summary']}")
            lines.append("")
        
        # Add flag if found
        if "flag" in output:
            lines.append(f"Flag: {output['flag']}")
            lines.append(f"Valid: {output.get('is_valid_flag', False)}")
            lines.append("")
        
        # Add challenge type
        if "challenge_type" in output:
            lines.append(f"Challenge Type: {output['challenge_type']}")
            lines.append("")
        
        # Add report IDs
        if "reports" in output:
            lines.append("Reports:")
            for report_type, report_id in output["reports"].items():
                lines.append(f"  {report_type}: {report_id}")
            lines.append("")
        
        # Add error if present
        if "error" in output:
            lines.append(f"Error: {output['error']}")
            lines.append("")
        
        # Add timestamp
        if "timestamp" in output:
            lines.append(f"Timestamp: {output['timestamp']}")
        
        return "\n".join(lines)
    
    def _format_markdown(self, output: Dict[str, Any]) -> str:
        """Format output as Markdown."""
        lines = []
        
        # Add title
        lines.append("# CTF Automator Result")
        lines.append("")
        
        # Add summary
        if "summary" in output:
            lines.append(f"**Summary:** {output['summary']}")
            lines.append("")
        
        # Add flag if found
        if "flag" in output:
            lines.append("## Flag")
            lines.append(f"```\n{output['flag']}\n```")
            lines.append(f"**Valid:** {output.get('is_valid_flag', False)}")
            lines.append("")
        
        # Add challenge type
        if "challenge_type" in output:
            lines.append(f"**Challenge Type:** {output['challenge_type']}")
            lines.append("")
        
        # Add report IDs
        if "reports" in output:
            lines.append("## Reports")
            for report_type, report_id in output["reports"].items():
                lines.append(f"- **{report_type}:** `{report_id}`")
            lines.append("")
        
        # Add error if present
        if "error" in output:
            lines.append("## Error")
            lines.append(f"```\n{output['error']}\n```")
            lines.append("")
        
        # Add timestamp
        if "timestamp" in output:
            lines.append(f"*Generated at: {output['timestamp']}*")
        
        return "\n".join(lines)
    
    def format_diagnostic_summary(self, diagnostic_report: Dict[str, Any]) -> str:
        """
        Format a diagnostic report summary.
        
        Args:
            diagnostic_report: Diagnostic report to format
            
        Returns:
            Formatted summary
        """
        lines = []
        
        # Add title
        lines.append("# Diagnostic Summary")
        lines.append("")
        
        # Add report ID and timestamp
        lines.append(f"**Report ID:** `{diagnostic_report.get('id', 'unknown')}`")
        lines.append(f"**Timestamp:** {diagnostic_report.get('timestamp', 'unknown')}")
        lines.append("")
        
        # Add report type
        lines.append(f"**Type:** {diagnostic_report.get('type', 'unknown')}")
        lines.append("")
        
        # Add metadata
        if "metadata" in diagnostic_report:
            lines.append("## Metadata")
            for key, value in diagnostic_report["metadata"].items():
                lines.append(f"- **{key}:** {value}")
            lines.append("")
        
        # Add content summary
        if "content" in diagnostic_report:
            lines.append("## Findings")
            content = diagnostic_report["content"]
            
            # Handle different report types
            if diagnostic_report.get("type") == "binary-diagnostic":
                if "file_type" in content:
                    lines.append(f"- **File Type:** {content['file_type']}")
                if "architecture" in content:
                    lines.append(f"- **Architecture:** {content['architecture']}")
                if "protections" in content:
                    lines.append("- **Protections:**")
                    for prot, enabled in content["protections"].items():
                        lines.append(f"  - {prot}: {'Enabled' if enabled else 'Disabled'}")
                if "interesting_functions" in content:
                    lines.append("- **Interesting Functions:**")
                    for func in content["interesting_functions"][:5]:  # Show first 5
                        lines.append(f"  - {func.get('name')} at {func.get('address')}")
                if "potential_vulnerabilities" in content:
                    lines.append("- **Potential Vulnerabilities:**")
                    for vuln in content["potential_vulnerabilities"]:
                        lines.append(f"  - {vuln.get('type')} in {vuln.get('location')} (confidence: {vuln.get('confidence')})")
            
            elif diagnostic_report.get("type") == "web-diagnostic":
                if "technologies" in content:
                    lines.append("- **Technologies:**")
                    for tech in content["technologies"]:
                        lines.append(f"  - {tech}")
                if "endpoints" in content:
                    lines.append("- **Endpoints:**")
                    for endpoint in content["endpoints"][:5]:  # Show first 5
                        lines.append(f"  - {endpoint}")
                if "potential_vulnerabilities" in content:
                    lines.append("- **Potential Vulnerabilities:**")
                    for vuln in content["potential_vulnerabilities"]:
                        lines.append(f"  - {vuln.get('type')} at {vuln.get('location')} (confidence: {vuln.get('confidence')})")
            
            else:
                # Generic handling for other report types
                for key, value in content.items():
                    if isinstance(value, dict):
                        lines.append(f"- **{key}:**")
                        for subkey, subvalue in value.items():
                            lines.append(f"  - {subkey}: {subvalue}")
                    elif isinstance(value, list):
                        lines.append(f"- **{key}:**")
                        for item in value[:5]:  # Show first 5 items
                            if isinstance(item, dict):
                                lines.append(f"  - {item}")
                            else:
                                lines.append(f"  - {item}")
                    else:
                        lines.append(f"- **{key}:** {value}")
        
        # Add recommendations
        if "recommendations" in diagnostic_report:
            lines.append("## Recommendations")
            for rec in diagnostic_report["recommendations"]:
                lines.append(f"- **{rec.get('action')}** ({rec.get('priority')}): {rec.get('focus', '')}")
        
        return "\n".join(lines)
    
    def format_analysis_summary(self, analysis_report: Dict[str, Any]) -> str:
        """
        Format an analysis report summary.
        
        Args:
            analysis_report: Analysis report to format
            
        Returns:
            Formatted summary
        """
        lines = []
        
        # Add title
        lines.append("# Analysis Summary")
        lines.append("")
        
        # Add report ID and timestamp
        lines.append(f"**Report ID:** `{analysis_report.get('id', 'unknown')}`")
        lines.append(f"**Timestamp:** {analysis_report.get('timestamp', 'unknown')}")
        lines.append("")
        
        # Add report type
        lines.append(f"**Type:** {analysis_report.get('type', 'unknown')}")
        lines.append("")
        
        # Add metadata
        if "metadata" in analysis_report:
            lines.append("## Metadata")
            for key, value in analysis_report["metadata"].items():
                lines.append(f"- **{key}:** {value}")
            lines.append("")
        
        # Add vulnerabilities
        if "content" in analysis_report and "vulnerabilities" in analysis_report["content"]:
            lines.append("## Vulnerabilities")
            for vuln in analysis_report["content"]["vulnerabilities"]:
                lines.append(f"### {vuln.get('name', 'Unknown Vulnerability')}")
                lines.append(f"- **Type:** {vuln.get('type', 'unknown')}")
                lines.append(f"- **Severity:** {vuln.get('severity', 'unknown')}")
                lines.append(f"- **Confidence:** {vuln.get('confidence', 'unknown')}")
                if "description" in vuln:
                    lines.append(f"- **Description:** {vuln['description']}")
                if "location" in vuln:
                    lines.append(f"- **Location:** {vuln['location']}")
                if "exploit_method" in vuln:
                    lines.append(f"- **Exploit Method:** {vuln['exploit_method']}")
                lines.append("")
        
        # Add analysis details
        if "content" in analysis_report and "analysis_details" in analysis_report["content"]:
            lines.append("## Analysis Details")
            details = analysis_report["content"]["analysis_details"]
            
            for key, value in details.items():
                if isinstance(value, dict):
                    lines.append(f"### {key}")
                    for subkey, subvalue in value.items():
                        lines.append(f"- **{subkey}:** {subvalue}")
                elif isinstance(value, list):
                    lines.append(f"### {key}")
                    for item in value:
                        if isinstance(item, dict):
                            for subkey, subvalue in item.items():
                                lines.append(f"- **{subkey}:** {subvalue}")
                        else:
                            lines.append(f"- {item}")
                else:
                    lines.append(f"### {key}")
                    lines.append(f"{value}")
                lines.append("")
        
        # Add recommendations
        if "recommendations" in analysis_report:
            lines.append("## Recommendations")
            for rec in analysis_report["recommendations"]:
                lines.append(f"- **{rec.get('action')}** ({rec.get('priority')}): {rec.get('details', '')}")
        
        return "\n".join(lines)
    
    def format_exploit_summary(self, exploit_report: Dict[str, Any]) -> str:
        """
        Format an exploit report summary.
        
        Args:
            exploit_report: Exploit report to format
            
        Returns:
            Formatted summary
        """
        lines = []
        
        # Add title
        lines.append("# Exploitation Summary")
        lines.append("")
        
        # Add report ID and timestamp
        lines.append(f"**Report ID:** `{exploit_report.get('id', 'unknown')}`")
        lines.append(f"**Timestamp:** {exploit_report.get('timestamp', 'unknown')}")
        lines.append("")
        
        # Add report type
        lines.append(f"**Type:** {exploit_report.get('type', 'unknown')}")
        lines.append("")
        
        # Add success status
        if "content" in exploit_report and "success" in exploit_report["content"]:
            success = exploit_report["content"]["success"]
            lines.append(f"**Success:** {'Yes' if success else 'No'}")
            lines.append("")
        
        # Add flag if found
        if "content" in exploit_report and "flag" in exploit_report["content"]:
            lines.append("## Flag")
            lines.append(f"```\n{exploit_report['content']['flag']}\n```")
            lines.append("")
        
        # Add exploit details
        if "content" in exploit_report and "exploit_details" in exploit_report["content"]:
            lines.append("## Exploit Details")
            details = exploit_report["content"]["exploit_details"]
            
            if "technique" in details:
                lines.append(f"- **Technique:** {details['technique']}")
            if "target" in details:
                lines.append(f"- **Target:** {details['target']}")
            if "payload" in details:
                lines.append("- **Payload:**")
                lines.append(f"```\n{details['payload']}\n```")
            if "execution_time" in details:
                lines.append(f"- **Execution Time:** {details['execution_time']} seconds")
            
            # Add any other details
            for key, value in details.items():
                if key not in ["technique", "target", "payload", "execution_time"]:
                    if isinstance(value, dict) or isinstance(value, list):
                        lines.append(f"- **{key}:** {json.dumps(value, indent=2)}")
                    else:
                        lines.append(f"- **{key}:** {value}")
            
            lines.append("")
        
        # Add execution log
        if "content" in exploit_report and "execution_log" in exploit_report["content"]:
            lines.append("## Execution Log")
            lines.append("```")
            lines.append(exploit_report["content"]["execution_log"])
            lines.append("```")
            lines.append("")
        
        # Add error if present
        if "content" in exploit_report and "error" in exploit_report["content"]:
            lines.append("## Error")
            lines.append(f"```\n{exploit_report['content']['error']}\n```")
            lines.append("")
        
        return "\n".join(lines)
