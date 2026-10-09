import os
from typing import List, Dict, Any, Tuple, Optional

# Try importing yara natively
HAS_NATIVE_YARA = False
try:
    import yara
    HAS_NATIVE_YARA = True
except ImportError:
    HAS_NATIVE_YARA = False

DEFAULT_DEFENSIVE_YARA_RULES = [
    {
        "rule_name": "Suspicious_Executable_Headers",
        "category": "ATTACHMENT_ANALYSIS",
        "severity": "HIGH",
        "description": "Detects PE executable header magic bytes (MZ) in non-exe files or attachments.",
        "rule_content": """
rule Suspicious_Executable_Headers {
    meta:
        description = "Detects PE executable header (MZ)"
        author = "MailForensics Defensive Team"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}
""",
        "is_enabled": True
    },
    {
        "rule_name": "Suspicious_VBA_Macro_Keywords",
        "category": "ATTACHMENT_ANALYSIS",
        "severity": "HIGH",
        "description": "Detects suspicious AutoOpen / Shell execution strings in Office document streams.",
        "rule_content": """
rule Suspicious_VBA_Macro_Keywords {
    meta:
        description = "Detects AutoOpen / Shell execution keywords"
        author = "MailForensics Defensive Team"
    strings:
        $a1 = "AutoOpen" ascii nocase
        $a2 = "Document_Open" ascii nocase
        $a3 = "Shell" ascii nocase
        $a4 = "WScript.Shell" ascii nocase
    condition:
        any of ($a*)
}
""",
        "is_enabled": True
    }
]

class YaraScanner:
    def __init__(self):
        self.engine_mode = "NATIVE" if HAS_NATIVE_YARA else "FALLBACK"

    def get_engine_status(self) -> Dict[str, Any]:
        yara_ver = "uninstalled"
        test_compiled = False
        test_scan_ok = False
        if HAS_NATIVE_YARA:
            try:
                yara_ver = getattr(yara, "__version__", "4.5.4")
                test_rule = yara.compile(source='rule HarmlessTestRule { strings: $a = "HARMLESS_BENIGN_PROBE" condition: $a }')
                test_compiled = True
                matches = test_rule.match(data=b"Testing HARMLESS_BENIGN_PROBE buffer")
                test_scan_ok = len(matches) == 1
            except Exception:
                test_scan_ok = False

        return {
            "status": "HEALTHY" if (HAS_NATIVE_YARA and test_scan_ok) else ("DEGRADED" if not HAS_NATIVE_YARA else "ERROR"),
            "YARA_AVAILABLE": HAS_NATIVE_YARA,
            "YARA_ENGINE": self.engine_mode,
            "YARA_VERSION": yara_ver,
            "engine": self.engine_mode,
            "has_native_yara": HAS_NATIVE_YARA,
            "rule_compilation_verified": test_compiled,
            "test_scan_verified": test_scan_ok,
            "description": f"Native YARA C-Engine v{yara_ver} operational" if HAS_NATIVE_YARA else "ENGINE: FALLBACK (Python pattern matching mode)."
        }

    def scan_file(self, file_path: str, rules_content_list: List[str]) -> List[Dict[str, Any]]:
        """
        Scan attachment file using YARA rules.
        """
        matches = []
        if not os.path.exists(file_path):
            return matches

        if HAS_NATIVE_YARA and rules_content_list:
            try:
                # Combine rules into a single string for compilation
                combined_rules = "\n".join(rules_content_list)
                compiled = yara.compile(source=combined_rules)
                yara_matches = compiled.match(file_path)
                for m in yara_matches:
                    matches.append({
                        "rule_name": m.rule,
                        "meta": m.meta,
                        "tags": m.tags,
                        "engine": "NATIVE"
                    })
                return matches
            except Exception:
                pass

        # FALLBACK ENGINE MODE (Basic regex / string search for safety)
        try:
            with open(file_path, "rb") as f:
                content = f.read(1024 * 1024) # Inspect first 1 MB
            
            # Simple fallback rules
            if content.startswith(b"MZ"):
                matches.append({
                    "rule_name": "Suspicious_Executable_Headers",
                    "meta": {"description": "PE Executable Header (MZ) detected"},
                    "engine": "FALLBACK"
                })
            if b"AutoOpen" in content or b"WScript.Shell" in content:
                matches.append({
                    "rule_name": "Suspicious_VBA_Macro_Keywords",
                    "meta": {"description": "VBA macro execution keyword detected"},
                    "engine": "FALLBACK"
                })
        except Exception:
            pass

        return matches

yara_scanner = YaraScanner()
