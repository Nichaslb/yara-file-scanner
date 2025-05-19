import yara
import os
import sys

def load_rules(rules_dir='rules'):
    rules = {}
    for filename in os.listdir(rules_dir):
        if filename.endswith('.yar') or filename.endswith('.yara'):
            rule_path = os.path.join(rules_dir, filename)
            rules[filename] = yara.compile(filepath=rule_path)
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
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <file-to-scan>")
        sys.exit(1)

    file_to_scan = sys.argv[1]
    if not os.path.exists(file_to_scan):
        print("File not found.")
        sys.exit(1)

    rules = load_rules()
    scan_file(file_to_scan, rules)

