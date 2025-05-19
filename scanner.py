import os
import sys
import yara
import argparse

# Get base directory where scanner.py lives
base_dir = os.path.dirname(os.path.abspath(__file__))

parser = argparse.ArgumentParser(description='YARA File Scanner')
parser.add_argument('--rules_dir', default=os.path.join(base_dir, 'rules'), help='Path to the YARA rules directory')
parser.add_argument('file_to_scan', help='Path to the file to scan')
args = parser.parse_args()

def load_rules(rules_dir):
    rules = {}
    for filename in os.listdir(rules_dir):
        if filename.endswith('.yar') or filename.endswith('.yara'):
            rule_path = os.path.join(rules_dir, filename)
            try:
                rules[filename] = yara.compile(filepath=rule_path)
            except yara.SyntaxError as e:
                print(f"Syntax error in {filename}: {e}")
            except Exception as e:
                print(f"Error compiling {filename}: {e}")
    return rules

def scan_file(file_path, rules):
    print(f"Scanning file: {file_path}")
    for name, rule in rules.items():
        matches = rule.match(filepath=file_path)
        if matches:
            print(f"[!] Matches found with rule '{name}':")
            for match in matches:
                print(f"    - {match.rule}")
        else:
            print(f"[-] No matches for rule '{name}'")

if __name__ == '__main__':
    # Build absolute path to file to scan
    file_to_scan = args.file_to_scan
    if not os.path.isabs(file_to_scan):
        file_to_scan = os.path.join(base_dir, file_to_scan)

    if not os.path.exists(file_to_scan):
        print(f"File not found: {file_to_scan}")
        sys.exit(1)

    rules = load_rules(args.rules_dir)
    scan_file(file_to_scan, rules)

