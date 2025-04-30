import logging
import pefile
from pathlib import Path
from typing import Tuple, Dict
from .binary_analyzer import BinaryAnalyzer

class PEScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.binary_analyzer = BinaryAnalyzer()

    def analyze_pe_file(self, file_path: str) -> Tuple[bool, str | None]:
        """Analyze PE (Portable Executable) files."""
        try:
            if not Path(file_path).suffix.lower() in ['.exe', '.dll', '.sys']:
                return True, None

            # First, perform binary analysis
            binary_results = self.binary_analyzer.analyze_binary(file_path)
            warnings = []

            if binary_results['is_suspicious']:
                warnings.append(self.binary_analyzer.get_summary(binary_results))

            # Then perform PE-specific analysis
            try:
                pe = pefile.PE(file_path)
                
                # Check for no imports (possibly packed)
                if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    warnings.append("No import directory found (possible packing)")
                
                # Check for suspicious sections
                for section in pe.sections:
                    section_name = section.Name.decode().strip('\x00')
                    if section.IMAGE_SCN_MEM_WRITE and section.IMAGE_SCN_MEM_EXECUTE:
                        warnings.append(f"Section {section_name} has both write and execute permissions")
                
                # Check for suspicious entry point
                if hasattr(pe, 'OPTIONAL_HEADER'):
                    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                    ep_section = None
                    for section in pe.sections:
                        if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                            ep_section = section.Name.decode().strip('\x00')
                            break
                    if ep_section != '.text':
                        warnings.append(f"Suspicious entry point in section {ep_section}")
                
                pe.close()
                
            except Exception as e:
                self.logger.error(f"Error in PE analysis: {str(e)}")
                warnings.append(f"Error analyzing PE structure: {str(e)}")
            
            if warnings:
                return False, "\n".join(warnings)
            return True, None
            
        except Exception as e:
            self.logger.error(f"Error analyzing file: {str(e)}")
            return False, "Error analyzing file format"

    def check_pe_sections(self, file_path: str) -> Tuple[bool, str | None]:
        """Check PE file sections for suspicious characteristics."""
        try:
            if not Path(file_path).suffix.lower() in ['.exe', '.dll', '.sys']:
                return True, None

            try:
                pe = pefile.PE(file_path)
                suspicious_sections = {b'UPX', b'ASPack', b'PECompact'}
                
                for section in pe.sections:
                    # Check for suspicious section names
                    if any(packer in section.Name for packer in suspicious_sections):
                        pe.close()
                        return False, f"Potential packer detected: {section.Name.decode().strip()}"
                    
                    # Check for high entropy in executable sections
                    if section.IMAGE_SCN_MEM_EXECUTE:
                        entropy = self._calculate_section_entropy(section.get_data())
                        if entropy > 7.0:
                            pe.close()
                            return False, f"High entropy ({entropy:.2f}) in executable section: {section.Name.decode().strip()}"
                
                pe.close()
                return True, None
                
            except Exception as e:
                self.logger.error(f"Error in PE section analysis: {str(e)}")
                return False, f"Error analyzing PE sections: {str(e)}"
            
        except Exception as e:
            self.logger.error(f"Error checking PE sections: {str(e)}")
            return False, "Error analyzing PE sections"

    def _calculate_section_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of a PE section."""
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * (p_x).bit_length()
        return entropy