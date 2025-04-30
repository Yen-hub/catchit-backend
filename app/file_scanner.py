import logging
from pathlib import Path
from typing import Dict, List, Set
from app.malware_dataset import MalwareDataset
from app.scanners.hash_scanner import HashScanner
from app.scanners.pe_scanner import PEScanner
from app.scanners.archive_scanner import ArchiveScanner
from app.scanners.content_scanner import ContentScanner
import re

class FileScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.dataset = MalwareDataset()
        
        # Configuration
        self.MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
        self.MAX_SCAN_SIZE = 10 * 1024 * 1024  # 10MB for content scanning
        
        # Load characteristics from dataset
        characteristics = self.dataset.get_characteristics()
        self.ENTROPY_THRESHOLD = characteristics['entropy_thresholds']['executable']['threshold']
        self.TEXT_ENTROPY_THRESHOLD = characteristics['entropy_thresholds']['text']['threshold']
        
        # Initialize specialized scanners
        self.hash_scanner = HashScanner()
        self.pe_scanner = PEScanner()
        self.archive_scanner = ArchiveScanner(
            max_file_size=self.MAX_FILE_SIZE,
            high_risk_extensions=self._get_high_risk_extensions()
        )
        self.content_scanner = ContentScanner(
            max_scan_size=self.MAX_SCAN_SIZE,
            exe_entropy_threshold=self.ENTROPY_THRESHOLD,
            text_entropy_threshold=self.TEXT_ENTROPY_THRESHOLD
        )
        
        # Compile patterns from dataset
        self.suspicious_patterns = self._compile_patterns()
        self.mime_mappings = self._get_mime_mappings()

    def _get_high_risk_extensions(self) -> Set[str]:
        """Get high-risk file extensions from dataset."""
        patterns = self.dataset.get_patterns()
        return set(
            patterns.get('file_patterns', {})
            .get('suspicious_extensions', {})
            .get('patterns', [])
        ) or {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js'}

    def _compile_patterns(self) -> List[Dict]:
        """Compile regex patterns from dataset."""
        patterns = []
        dataset_patterns = self.dataset.get_patterns()
        
        for category, pattern_group in dataset_patterns.items():
            if isinstance(pattern_group, dict):
                for pattern_name, pattern_data in pattern_group.items():
                    if isinstance(pattern_data, dict) and 'patterns' in pattern_data:
                        for pattern in pattern_data['patterns']:
                            if isinstance(pattern, str):
                                try:
                                    if not pattern.startswith('(?i)'):
                                        pattern = f"(?i){pattern}"
                                    patterns.append({
                                        'pattern': re.compile(pattern.encode() if isinstance(pattern, str) else pattern),
                                        'name': pattern_name,
                                        'severity': pattern_data.get('severity', 'medium'),
                                        'description': pattern_data.get('description', '')
                                    })
                                except Exception as e:
                                    self.logger.warning(f"Failed to compile pattern {pattern}: {str(e)}")
        return patterns

    def _get_mime_mappings(self) -> Dict:
        """Get MIME type mappings for file type validation."""
        return {
            '.txt': ['text/plain'],
            '.pdf': ['application/pdf'],
            '.doc': ['application/msword'],
            '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
            '.xls': ['application/vnd.ms-excel'],
            '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
            '.zip': ['application/zip', 'application/x-zip-compressed'],
            '.exe': ['application/x-msdownload', 'application/x-dosexec'],
            '.dll': ['application/x-msdownload', 'application/x-dosexec']
        }

    def check_file_size(self, file_path: str) -> tuple[bool, str | None]:
        """Check if file size is within limits."""
        size = Path(file_path).stat().st_size
        if size > self.MAX_FILE_SIZE:
            return False, f"File size ({size/1024/1024:.1f}MB) exceeds maximum allowed size ({self.MAX_FILE_SIZE/1024/1024}MB)"
        return True, None

    def scan_file(self, file_path: str) -> Dict:
        """Main method to scan a file for malware."""
        results = {
            'file_name': Path(file_path).name,
            'file_size': Path(file_path).stat().st_size,
            'scan_results': [],
            'is_malicious': False,
            'hashes': self.hash_scanner.calculate_file_hash(file_path),
            'threat_level': 'clean'
        }
        
        # Track severity for overall threat level
        severity_scores = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'clean': 0
        }
        max_severity = 'clean'
        
        # Check file size first
        is_safe, message = self.check_file_size(file_path)
        if not is_safe:
            results['scan_results'].append({
                'check': 'size_check',
                'status': 'malicious',
                'severity': 'medium',
                'message': message
            })
            results['is_malicious'] = True
            max_severity = 'medium'
        
        # Check file extension risk
        if Path(file_path).suffix.lower() in self._get_high_risk_extensions():
            results['scan_results'].append({
                'check': 'extension_check',
                'status': 'warning',
                'severity': 'medium',
                'message': 'High-risk file extension detected'
            })
            max_severity = max(max_severity, 'medium', key=lambda x: severity_scores.get(x, 0))
        
        # Run all security checks
        checks = [
            ('signature_check', lambda f: self.hash_scanner.check_file_signature(f, self.dataset.get_signatures()), 'critical'),
            ('content_type_check', lambda f: self.content_scanner.check_file_type(f, self.mime_mappings), 'high'),
            ('pe_analysis', self.pe_scanner.analyze_pe_file, 'high'),
            ('content_check', lambda f: self.content_scanner.scan_content(f, self.suspicious_patterns), 'high'),
            ('archive_check', self.archive_scanner.scan_archive, 'high')
        ]
        
        for check_name, check_func, severity in checks:
            try:
                is_safe, message = check_func(file_path)
                results['scan_results'].append({
                    'check': check_name,
                    'status': 'clean' if is_safe else 'malicious',
                    'severity': severity if not is_safe else 'clean',
                    'message': message if not is_safe else 'No threats detected'
                })
                if not is_safe:
                    results['is_malicious'] = True
                    max_severity = max(max_severity, severity, key=lambda x: severity_scores.get(x, 0))
            except Exception as e:
                self.logger.error(f"Error in {check_name}: {str(e)}")
                results['scan_results'].append({
                    'check': check_name,
                    'status': 'error',
                    'severity': 'medium',
                    'message': f"Error during scan: {str(e)}"
                })
        
        results['threat_level'] = max_severity
        return results