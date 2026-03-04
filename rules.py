import re

# Simple signature patterns (educational / lab)
RULES = [
    ("SQLi", re.compile(r"(\bor\b\s+1=1\b|union\s+select|select\s+.+\s+from|'\s*--|--\s|/\*|\*/)", re.I)),
    ("XSS", re.compile(r"(<script|%3cscript|onerror\s*=|onload\s*=|javascript:)", re.I)),
    ("LFI", re.compile(r"(\.\./|\.\.\\|/etc/passwd|windows/system32|boot.ini)", re.I)),
    ("Traversal", re.compile(r"(\.\./|\.\.\\)", re.I)),
    ("CmdInjection", re.compile(r"(;|\|\||&&|\|)\s*(cat|whoami|id|uname|curl|wget|bash|sh)\b", re.I)),
]

def match_rules(text: str):
    hits = []
    for name, pattern in RULES:
        if pattern.search(text):
            hits.append(name)
    return hits
