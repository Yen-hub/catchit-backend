import hashlib
import logging
from typing import Dict

class HashScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def calculate_file_hash(self, file_path: str) -> Dict[str, str]:
        """Calculate multiple hashes of a file."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest()
        }

    def check_file_signature(self, file_path: str, signatures: Dict) -> tuple[bool, str | None]:
        """Check if file matches known malware signatures."""
        hashes = self.calculate_file_hash(file_path)
        
        if hashes['md5'] in signatures:
            malware_info = signatures[hashes['md5']]
            return False, f"Matched known malware signature: {malware_info['name']} ({malware_info['type']}) - {malware_info['description']}"
        return True, None