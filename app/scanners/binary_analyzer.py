import logging
import struct
import math
from typing import Dict, List, Set, Tuple
from pathlib import Path

class BinaryAnalyzer:
    """Analyzes binary files for suspicious characteristics."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Common suspicious byte sequences
        self.suspicious_sequences = {
            b'\x4D\x5A': "DOS MZ header",  # DOS/PE executable
            b'\x7F\x45\x4C\x46': "ELF header",  # Linux executable
            b'\xCA\xFE\xBA\xBE': "Mach-O header",  # macOS executable
            b'\x50\x4B\x03\x04': "ZIP signature",  # ZIP archive
            b'\x52\x61\x72\x21': "RAR signature",  # RAR archive
            b'\x75\x73\x74\x61\x72': "TAR signature",  # TAR archive
        }
        
        # Suspicious strings that might indicate malicious intent
        self.suspicious_strings = [
            b"CreateProcess",
            b"WinExec",
            b"ShellExecute",
            b"RegCreateKey",
            b"WriteProcessMemory",
            b"CreateRemoteThread",
            b"VirtualAlloc",
            b"LoadLibrary",
            b"URLDownloadToFile",
            b"StartService",
            b"CreateService",
            b"SetWindowsHookEx",
        ]

    def analyze_binary(self, file_path: str) -> Dict:
        """
        Perform comprehensive analysis of a binary file.
        
        Returns:
            Dict containing analysis results including:
            - File format identification
            - Embedded file signatures
            - Suspicious API calls
            - Statistical analysis
            - Entropy analysis
        """
        results = {
            'format': None,
            'embedded_signatures': [],
            'suspicious_apis': [],
            'statistics': {},
            'entropy': 0.0,
            'is_suspicious': False,
            'warnings': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
                # Check file signatures
                self._check_signatures(content, results)
                
                # Look for suspicious strings
                self._find_suspicious_strings(content, results)
                
                # Calculate statistics and entropy
                results['statistics'] = self._calculate_statistics(content)
                results['entropy'] = self._calculate_entropy(content)
                
                # Check for potential code injection
                self._check_code_injection(content, results)
                
                # Set suspicious flag if any issues were found
                results['is_suspicious'] = (
                    len(results['suspicious_apis']) > 0 or
                    len(results['warnings']) > 0 or
                    results['entropy'] > 7.0
                )
                
        except Exception as e:
            self.logger.error(f"Error analyzing binary file: {str(e)}")
            results['error'] = str(e)
        
        return results

    def _check_signatures(self, content: bytes, results: Dict) -> None:
        """Check for known file signatures in the content."""
        for signature, description in self.suspicious_sequences.items():
            if signature in content:
                results['embedded_signatures'].append({
                    'signature': signature.hex(),
                    'description': description,
                    'offset': content.find(signature)
                })

    def _find_suspicious_strings(self, content: bytes, results: Dict) -> None:
        """Search for suspicious strings and API calls."""
        for sus_string in self.suspicious_strings:
            if sus_string in content:
                results['suspicious_apis'].append({
                    'api': sus_string.decode(errors='ignore'),
                    'count': content.count(sus_string),
                    'first_offset': content.find(sus_string)
                })

    def _calculate_statistics(self, content: bytes) -> Dict:
        """Calculate statistical properties of the binary content."""
        stats = {
            'size': len(content),
            'null_bytes': content.count(b'\x00'),
            'printable_chars': sum(1 for b in content if 32 <= b <= 126),
            'byte_distribution': {},
        }
        
        # Calculate byte distribution
        for b in range(256):
            count = content.count(bytes([b]))
            if count > 0:
                stats['byte_distribution'][b] = count
        
        # Calculate ratios
        total_bytes = len(content)
        if total_bytes > 0:
            stats['null_ratio'] = stats['null_bytes'] / total_bytes
            stats['printable_ratio'] = stats['printable_chars'] / total_bytes
        
        return stats

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of the binary data."""
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    def _check_code_injection(self, content: bytes, results: Dict) -> None:
        """Check for potential code injection patterns."""
        # Look for common shellcode patterns
        shellcode_patterns = [
            (b'\x90' * 10, "NOP sled detected"),  # NOP sled
            (b'\x31\xc0\x50\x68', "Potential shellcode"),  # Common shellcode start
            (b'\x68\x63\x6d\x64', "CMD string reference"),  # 'cmd' string push
        ]
        
        for pattern, description in shellcode_patterns:
            if pattern in content:
                results['warnings'].append({
                    'type': 'code_injection',
                    'description': description,
                    'offset': content.find(pattern)
                })

    def get_summary(self, results: Dict) -> str:
        """Generate a human-readable summary of the analysis results."""
        summary = []
        
        if results.get('error'):
            return f"Error during analysis: {results['error']}"
        
        if results['is_suspicious']:
            summary.append("⚠️ File contains suspicious characteristics:")
            
            if results['embedded_signatures']:
                summary.append("\nEmbedded signatures found:")
                for sig in results['embedded_signatures']:
                    summary.append(f"- {sig['description']} at offset {sig['offset']}")
            
            if results['suspicious_apis']:
                summary.append("\nSuspicious API calls found:")
                for api in results['suspicious_apis']:
                    summary.append(f"- {api['api']} (found {api['count']} times)")
            
            if results['warnings']:
                summary.append("\nWarnings:")
                for warning in results['warnings']:
                    summary.append(f"- {warning['description']}")
            
            if results['entropy'] > 7.0:
                summary.append(f"\nHigh entropy detected: {results['entropy']:.2f}")
        else:
            summary.append("✅ No suspicious characteristics detected")
        
        stats = results['statistics']
        summary.append(f"\nStatistics:")
        summary.append(f"- File size: {stats['size']:,} bytes")
        summary.append(f"- Printable characters: {stats['printable_ratio']*100:.1f}%")
        summary.append(f"- Null bytes: {stats['null_ratio']*100:.1f}%")
        summary.append(f"- Entropy: {results['entropy']:.2f}")
        
        return "\n".join(summary)