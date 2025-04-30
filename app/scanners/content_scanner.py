import logging
import math
import re
from typing import Dict, List, Tuple
from pathlib import Path

class ContentScanner:
    def __init__(self, max_scan_size: int, exe_entropy_threshold: float, text_entropy_threshold: float):
        self.logger = logging.getLogger(__name__)
        self.MAX_SCAN_SIZE = max_scan_size
        self.EXE_ENTROPY_THRESHOLD = exe_entropy_threshold
        self.TEXT_ENTROPY_THRESHOLD = text_entropy_threshold

    def scan_content(self, file_path: str, patterns: List[Dict]) -> Tuple[bool, str | None]:
        """Scan file contents for suspicious patterns."""
        try:
            size = Path(file_path).stat().st_size
            read_size = min(size, self.MAX_SCAN_SIZE)
            
            with open(file_path, 'rb') as f:
                content = f.read(read_size)
            
            # Check for suspicious patterns
            detections = []
            for pattern_data in patterns:
                if 'pattern' in pattern_data:
                    matches = pattern_data['pattern'].finditer(content)
                    for match in matches:
                        context = content[max(0, match.start()-50):min(len(content), match.end()+50)]
                        detections.append({
                            'pattern_name': pattern_data['name'],
                            'severity': pattern_data.get('severity', 'medium'),
                            'description': pattern_data.get('description', ''),
                            'context': context.decode(errors='ignore')
                        })
            
            if detections:
                messages = []
                for detection in detections:
                    messages.append(
                        f"Detected {detection['pattern_name']} ({detection['severity']} severity): "
                        f"{detection['description']} - Context: ...{detection['context']}..."
                    )
                return False, "Multiple suspicious patterns found:\n" + "\n".join(messages)
            
            # Entropy analysis
            if Path(file_path).suffix.lower() not in ['.zip', '.rar', '.7z', '.gz']:
                entropy = self._calculate_entropy(content)
                threshold = (
                    self.EXE_ENTROPY_THRESHOLD 
                    if Path(file_path).suffix.lower() in ['.exe', '.dll', '.sys'] 
                    else self.TEXT_ENTROPY_THRESHOLD
                )
                
                if entropy > threshold:
                    return False, f"High entropy detected ({entropy:.2f}), possible encryption or packing"
            
            return True, None
        except Exception as e:
            self.logger.error(f"Error scanning file contents: {str(e)}")
            return False, "Error scanning file contents"

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data with sliding window."""
        if not data:
            return 0.0
        
        # Use sliding window for large files
        window_size = min(len(data), 1024 * 1024)  # 1MB window
        max_entropy = 0.0
        
        for i in range(0, len(data) - window_size + 1, window_size // 2):
            window = data[i:i + window_size]
            entropy = 0.0
            for x in range(256):
                p_x = window.count(x) / len(window)
                if p_x > 0:
                    entropy += -p_x * math.log2(p_x)
            max_entropy = max(max_entropy, entropy)
        
        return max_entropy

    def check_file_type(self, file_path: str, mime_mappings: Dict) -> Tuple[bool, str | None]:
        """Check if the file's content matches its extension."""
        try:
            import magic
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)
            declared_ext = Path(file_path).suffix.lower()
            
            if declared_ext in mime_mappings:
                if file_type not in mime_mappings[declared_ext]:
                    return False, f"File type mismatch: Declared as {declared_ext}, but detected as {file_type}"
            
            return True, None
        except Exception as e:
            self.logger.error(f"Error checking file type: {str(e)}")
            return False, "Error analyzing file type"