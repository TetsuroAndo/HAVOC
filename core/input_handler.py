"""
Input Handler for CTF Automator.
Processes various types of input for CTF challenges.
"""
import os
import re
import logging
import datetime
import requests
from typing import Dict, Any, Union
from urllib.parse import urlparse


class InputHandler:
    """
    Handles and processes various types of input for CTF challenges.
    """
    
    def __init__(self, logger, config):
        """
        Initialize the input handler.
        
        Args:
            logger: Logger instance
            config: Configuration dictionary
        """
        self.logger = logger
        self.config = config
        self.workspace_dir = config.get("general", {}).get("workspace_dir", "data/workspace")
        
        # Create workspace directory if it doesn't exist
        os.makedirs(self.workspace_dir, exist_ok=True)
        os.makedirs(os.path.join(self.workspace_dir, "temp"), exist_ok=True)
        os.makedirs(os.path.join(self.workspace_dir, "extracted"), exist_ok=True)
    
    def process(self, input_data: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process the input data.
        
        Args:
            input_data: Input data (file path, URL, or text)
            
        Returns:
            Dict containing processed input information
        """
        if isinstance(input_data, str):
            # Check if input is a file path
            if os.path.exists(input_data):
                return self._process_file(input_data)
            # Check if input is a URL
            elif self._is_url(input_data):
                return self._process_url(input_data)
            # Otherwise, treat as text
            else:
                return self._process_text(input_data)
        elif isinstance(input_data, dict):
            # Already processed input
            return input_data
        else:
            self.logger.error(f"Unsupported input type: {type(input_data)}")
            raise ValueError(f"Unsupported input type: {type(input_data)}")
    
    def _is_url(self, text: str) -> bool:
        """Check if the input is a URL."""
        try:
            result = urlparse(text)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _process_file(self, file_path: str) -> Dict[str, Any]:
        """Process a file input."""
        self.logger.info(f"Processing file: {file_path}")
        
        # Get absolute path
        abs_path = os.path.abspath(file_path)
        
        # Determine file type
        file_type = self._determine_file_type(abs_path)
        file_size = os.path.getsize(abs_path)
        file_name = os.path.basename(abs_path)
        
        # Create a copy in the workspace if needed
        workspace_path = abs_path
        if not abs_path.startswith(self.workspace_dir):
            workspace_path = os.path.join(self.workspace_dir, "temp", file_name)
            self._copy_file(abs_path, workspace_path)
        
        # Extract file if it's an archive
        extracted_path = None
        if file_type in ["zip", "tar", "gz", "rar"]:
            extracted_path = self._extract_archive(workspace_path, file_type)
        
        return {
            "type": "file",
            "path": abs_path,
            "workspace_path": workspace_path,
            "extracted_path": extracted_path,
            "file_name": file_name,
            "file_type": file_type,
            "size": file_size,
            "timestamp": datetime.datetime.now().isoformat()
        }
    
    def _process_url(self, url: str) -> Dict[str, Any]:
        """Process a URL input."""
        self.logger.info(f"Processing URL: {url}")
        
        # Validate URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            # Perform a HEAD request to check if the URL is accessible
            response = requests.head(url, timeout=10)
            response.raise_for_status()
            
            # Get content type and size if available
            content_type = response.headers.get('Content-Type', 'unknown')
            content_size = response.headers.get('Content-Length', 'unknown')
            
            return {
                "type": "url",
                "url": url,
                "content_type": content_type,
                "content_size": content_size,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "timestamp": datetime.datetime.now().isoformat()
            }
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Error accessing URL {url}: {e}")
            return {
                "type": "url",
                "url": url,
                "error": str(e),
                "timestamp": datetime.datetime.now().isoformat()
            }
    
    def _process_text(self, text: str) -> Dict[str, Any]:
        """Process a text input."""
        self.logger.info("Processing text input")
        
        # Save text to a file in the workspace
        file_path = os.path.join(self.workspace_dir, "temp", "input.txt")
        with open(file_path, 'w') as f:
            f.write(text)
        
        return {
            "type": "text",
            "content": text,
            "file_path": file_path,
            "length": len(text),
            "timestamp": datetime.datetime.now().isoformat()
        }
    
    def _determine_file_type(self, file_path: str) -> str:
        """
        Determine the type of file using file extension and magic bytes.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File type as a string
        """
        # First, check by extension
        _, ext = os.path.splitext(file_path)
        if ext:
            return ext.lower()[1:]
        
        # If no extension, try to determine by content (magic bytes)
        try:
            import magic
            file_type = magic.from_file(file_path, mime=True)
            return file_type.split('/')[-1]
        except ImportError:
            self.logger.warning("python-magic not installed, falling back to basic file type detection")
            
            # Fallback: check first few bytes
            with open(file_path, 'rb') as f:
                header = f.read(8)
            
            # Check for common file signatures
            if header.startswith(b'\x7fELF'):
                return "elf"
            elif header.startswith(b'MZ'):
                return "exe"
            elif header.startswith(b'\x89PNG'):
                return "png"
            elif header.startswith(b'\xff\xd8'):
                return "jpg"
            elif header.startswith(b'GIF8'):
                return "gif"
            elif header.startswith(b'PK\x03\x04'):
                return "zip"
            else:
                # Try to determine if it's text
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        f.read(1024)
                    return "txt"
                except UnicodeDecodeError:
                    return "bin"
    
    def _copy_file(self, source_path: str, dest_path: str) -> None:
        """
        Copy a file to the workspace.
        
        Args:
            source_path: Source file path
            dest_path: Destination file path
        """
        import shutil
        try:
            shutil.copy2(source_path, dest_path)
            self.logger.info(f"Copied file to workspace: {dest_path}")
        except Exception as e:
            self.logger.error(f"Error copying file to workspace: {e}")
    
    def _extract_archive(self, archive_path: str, archive_type: str) -> str:
        """
        Extract an archive to the workspace.
        
        Args:
            archive_path: Path to the archive
            archive_type: Type of archive
            
        Returns:
            Path to the extracted directory
        """
        import shutil
        import tempfile
        
        extract_dir = os.path.join(self.workspace_dir, "extracted", 
                                  os.path.basename(archive_path).split('.')[0])
        
        try:
            os.makedirs(extract_dir, exist_ok=True)
            
            if archive_type == "zip":
                shutil.unpack_archive(archive_path, extract_dir, format="zip")
            elif archive_type in ["tar", "gz", "bz2"]:
                shutil.unpack_archive(archive_path, extract_dir, format="tar")
            else:
                self.logger.warning(f"Unsupported archive type: {archive_type}")
                return None
            
            self.logger.info(f"Extracted archive to: {extract_dir}")
            return extract_dir
        except Exception as e:
            self.logger.error(f"Error extracting archive: {e}")
            return None
