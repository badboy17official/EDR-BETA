import math
import re
import lief
import structlog
from typing import Dict, Any

logger = structlog.get_logger()

def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    entropy = 0.0
    data_length = len(data)
    # Count byte occurrences
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
        
    for count in byte_counts:
        if count > 0:
            p_x = float(count) / data_length
            entropy += - p_x * math.log2(p_x)
    return entropy

def extract_strings(data: bytes, min_length: int = 5) -> list[str]:
    """Extracts printable ASCII strings of a minimum length."""
    # Pattern looks for sequences of printable ASCII chars
    pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
    ascii_strings = re.findall(pattern, data)
    return [s.decode('utf-8', 'ignore') for s in ascii_strings]

def analyze_file(file_path: str) -> Dict[str, Any]:
    """
    Performs static analysis on a given file.
    Detects if it is PE/ELF, calculates entropy, and extracts strings/imports.
    """
    logger.info("starting_static_analysis", file_path=file_path)
    
    with open(file_path, "rb") as f:
        file_data = f.read()
        
    entropy = calculate_entropy(file_data)
    strings = extract_strings(file_data)
    
    # Defaults
    result = {
        "file_type": "UNKNOWN",
        "entropy": round(entropy, 4),
        "strings_count": len(strings),
        "imports": [],
        "imports_count": 0,
        "metadata": {
            "size": len(file_data)
        }
    }
    
    # Parse with LIEF
    try:
        binary = lief.parse(file_path)
        if binary is not None:
            if isinstance(binary, lief.PE.Binary):
                result["file_type"] = "PE"
                for imported_library in binary.imports:
                    for entry in imported_library.entries:
                        if entry.name:
                            result["imports"].append(f"{imported_library.name}:{entry.name}")
                            
            elif isinstance(binary, lief.ELF.Binary):
                result["file_type"] = "ELF"
                # Use dynamic symbols representing imported functions in ELF
                for sym in binary.imported_symbols:
                    if sym.name:
                        result["imports"].append(sym.name)
                        
            result["imports_count"] = len(result["imports"])
            
    except Exception as e:
        logger.warning("lief_parsing_failed", file_path=file_path, error=str(e))
        
    logger.info("static_analysis_completed", 
                file_type=result["file_type"], 
                entropy=result["entropy"])
                
    return result
