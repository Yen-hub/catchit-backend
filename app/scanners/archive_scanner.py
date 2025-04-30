import logging
import zipfile
from typing import Set, Tuple
from pathlib import Path

class ArchiveScanner:
    def __init__(self, max_file_size: int, high_risk_extensions: Set[str]):
        self.logger = logging.getLogger(__name__)
        self.MAX_FILE_SIZE = max_file_size
        self.high_risk_extensions = high_risk_extensions

    def scan_archive(self, file_path: str) -> Tuple[bool, str | None]:
        """Analyze archive files for suspicious content."""
        if not zipfile.is_zipfile(file_path):
            return True, None
            
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                total_size = 0
                suspicious_ratio = 0
                
                for info in zip_ref.infolist():
                    # Check compression ratio (zip bomb detection)
                    if info.compress_size > 0:
                        ratio = info.file_size / info.compress_size
                        if ratio > 1000:  # Compression ratio > 1000:1
                            return False, f"Suspicious compression ratio in {info.filename}: {ratio:.1f}:1"
                        
                    # Check total uncompressed size
                    total_size += info.file_size
                    if total_size > self.MAX_FILE_SIZE * 2:
                        return False, "Archive contents too large when uncompressed"
                    
                    # Check for suspicious files
                    if any(info.filename.lower().endswith(ext) for ext in self.high_risk_extensions):
                        return False, f"Archive contains high-risk file: {info.filename}"
                        
                    # Check for hidden files
                    if info.filename.startswith('__MACOSX') or info.filename.startswith('.'):
                        suspicious_ratio += 1
                
                if suspicious_ratio / len(zip_ref.infolist()) > 0.5:
                    return False, "High ratio of hidden/suspicious files in archive"
                        
            return True, None
        except Exception as e:
            self.logger.error(f"Error analyzing archive: {str(e)}")
            return False, "Error analyzing archive contents"

    def check_nested_archives(self, file_path: str) -> Tuple[bool, str | None]:
        """Check for suspicious nested archives."""
        if not zipfile.is_zipfile(file_path):
            return True, None
            
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                archive_count = 0
                total_files = len(zip_ref.namelist())
                
                for info in zip_ref.namelist():
                    if info.lower().endswith(('.zip', '.rar', '.7z', '.tar', '.gz')):
                        archive_count += 1
                        
                # If more than 30% of files are archives, flag as suspicious
                if total_files > 0 and (archive_count / total_files) > 0.3:
                    return False, f"High ratio of nested archives detected ({archive_count}/{total_files} files)"
            
            return True, None
        except Exception as e:
            self.logger.error(f"Error checking nested archives: {str(e)}")
            return False, "Error analyzing nested archives"