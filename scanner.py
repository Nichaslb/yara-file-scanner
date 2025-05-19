import yara
import os
import sys
import argparse

# ---- Configuration ----
MAX_FILE_SIZE_MB = 10
ALLOWED_EXTENSIONS = {'.exe', '.txt'}

# ------------------------

# Parse command-line arguments
parser = argparse.ArgumentParser(description='YARA File Scanner')
parser.add_argument('--rules', default='rules/sample_rule.yar', help='Path to the YARA rules file')
parser.add_argument('file_to_scan', help='Path to the file you want to scan')
args = parser.parse_args()

# ---- File validation functions ----

def is_valid_file(path):
    if not os.path.exists(path):
        print(f"[ERROR] File does not exist: {path}")
        return False
    if not os.path.isfile(path):
        print(f"[ERROR] Not a regular file: {path}")
        return False
    _, ext = os.path.splitext(path)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        print(f"[ERROR] File extension '{ext}' is not allowed.")
        return False
    size_mb = os.path.getsize(path) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        print(f"[ERROR] File size {size_mb:.2f} MB exceeds limit of {MAX_FILE_SIZE_MB} MB.")
        return False
    return True

# ---- Load rules with error handling ----

def load_rules(rules_dir='rules'):
    rules = {}
    for filename in os.listdir(rules_dir):
        if filename.endswith('.yar') or filename.endswith('.yara'):
            rule_path = os.path.join(rules_dir, filename)
            try:
                rules[filename] = yara.compile(filepath=rule_path)
            except yara.SyntaxError as e:
                print(f"[ERROR] Syntax error in rule {filename}: {e}")
            except Exception as e:
                print(f"[ERROR] Failed to compile {filename}: {e}")
    return rules

# ---- Scanning logic ----

def scan_file(file_path, rules):
    print(f"Scanning file: {os.path.abspath(file_path)}")
    for name, rule in rules.items():
        try:
            matches = rule.match(filepath=file_path)
            if matches:
                print(f"[!] Matches found with rule '{name}':")
                for match in matches:
                    print(f"    - {match.rule}")
            else:
                print(f"[-] No matches for rule '{name}'")
        except Exception as e:
            print(f"[ERROR] Rule '{name}' failed to scan '{file_path}': {e}")

# ---- Main ----

if __name__ == '__main__':
    file_to_scan = args.file_to_scan

    if not is_valid_file(file_to_scan):
        sys.exit(1)

    rules = load_rules()
    if not rules:
        print("[ERROR] No valid YARA rules were loaded.")
        sys.exit(1)

    scan_file(file_to_scan, rules)

