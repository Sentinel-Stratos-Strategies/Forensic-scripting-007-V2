#!/usr/bin/env python3
"""
Signature-Based Detection Script for LLM/AI Processes
This script uses pattern matching and signature analysis to identify
hidden LLM/AI processes in the system.
"""

import os
import re
import subprocess
import json
from datetime import datetime
from pathlib import Path


class SignatureDetector:
    # Configuration constants
    MIN_MODEL_FILE_SIZE_MB = 1  # Minimum file size in MB to be considered a model file

    def __init__(self):
        self.findings = []

        # File signatures for common LLM frameworks
        self.file_signatures = {
            'pytorch': ['.pt', '.pth', 'torch', 'pytorch'],
            'tensorflow': ['.pb', '.h5', 'tensorflow', 'tf_'],
            'huggingface': ['transformers', 'tokenizer.json', 'config.json'],
            'onnx': ['.onnx'],
            'llama': ['llama', 'alpaca', 'vicuna'],
        }

        # Process command signatures
        self.command_signatures = [
            r'python.*model.*\.py',
            r'.*inference.*server',
            r'.*api.*server.*\-\-model',
            r'uvicorn.*main:app',
            r'flask.*run.*model',
            r'serve.*\-\-model\-path',
            r'.*tokenizer.*',
            r'.*embedding.*server',
        ]

        # Environment variable signatures
        self.env_signatures = [
            'CUDA_VISIBLE_DEVICES',
            'TRANSFORMERS_CACHE',
            'HF_HOME',
            'TORCH_HOME',
            'OPENAI_API_KEY',
            'ANTHROPIC_API_KEY',
        ]

        # Port signatures (common API server ports)
        self.suspicious_ports = [8000, 8080, 5000, 7860, 11434]

    def scan_process_cmdlines(self):
        """Scan all process command lines for signatures"""
        print("[*] Scanning process command lines for LLM/AI signatures...")

        try:
            # Use ps to get process information
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True,
                timeout=10
            )

            lines = result.stdout.split('\n')
            for line in lines[1:]:  # Skip header
                if not line.strip():
                    continue

                for pattern in self.command_signatures:
                    if re.search(pattern, line, re.IGNORECASE):
                        parts = line.split(None, 10)
                        if len(parts) >= 11:
                            self.findings.append({
                                'type': 'command_signature',
                                'pattern': pattern,
                                'user': parts[0],
                                'pid': parts[1],
                                'cpu': parts[2],
                                'mem': parts[3],
                                'command': parts[10][:200]
                            })
                        break

        except Exception as e:
            print(f"[!] Error scanning processes: {e}")

    def scan_environment_variables(self):
        """Scan environment variables for LLM/AI indicators"""
        print("[*] Scanning environment variables for LLM/AI indicators...")

        try:
            # Scan /proc/<pid>/environ for all processes
            for proc_dir in Path('/proc').glob('[0-9]*'):
                try:
                    pid = proc_dir.name
                    environ_file = proc_dir / 'environ'

                    if environ_file.exists():
                        with open(environ_file, 'rb') as f:
                            environ_data = f.read().decode('utf-8', errors='ignore')
                            env_vars = environ_data.split('\x00')

                            for env_var in env_vars:
                                if '=' in env_var:
                                    key, value = env_var.split('=', 1)
                                    if key in self.env_signatures:
                                        cmdline_file = proc_dir / 'cmdline'
                                        cmdline = ''
                                        if cmdline_file.exists():
                                            with open(cmdline_file, 'rb') as cf:
                                                cmdline = cf.read().decode('utf-8', errors='ignore').replace('\x00', ' ')

                                        self.findings.append({
                                            'type': 'environment_variable',
                                            'pid': pid,
                                            'env_key': key,
                                            'env_value': value[:100],  # Truncate for security
                                            'cmdline': cmdline[:200]
                                        })

                except (PermissionError, FileNotFoundError, ProcessLookupError):
                    continue

        except Exception as e:
            print(f"[!] Error scanning environment: {e}")

    def scan_open_files(self):
        """Scan for open files matching LLM signatures"""
        print("[*] Scanning open files for LLM/AI model files...")

        try:
            result = subprocess.run(
                ['lsof', '-n'],
                capture_output=True,
                text=True,
                timeout=30
            )

            lines = result.stdout.split('\n')
            for line in lines[1:]:  # Skip header
                if not line.strip():
                    continue

                # Check for file signature matches
                for framework, signatures in self.file_signatures.items():
                    for sig in signatures:
                        if sig in line.lower():
                            parts = line.split(None, 8)
                            if len(parts) >= 9:
                                self.findings.append({
                                    'type': 'open_file_signature',
                                    'framework': framework,
                                    'signature': sig,
                                    'command': parts[0],
                                    'pid': parts[1],
                                    'user': parts[2],
                                    'file': parts[8] if len(parts) > 8 else 'N/A'
                                })
                            break

        except FileNotFoundError:
            print("[!] lsof not found. Skipping open files scan.")
        except Exception as e:
            print(f"[!] Error scanning open files: {e}")

    def scan_listening_ports(self):
        """Scan for processes listening on suspicious ports"""
        print("[*] Scanning for processes on suspicious ports...")

        try:
            result = subprocess.run(
                ['netstat', '-tlnp'],
                capture_output=True,
                text=True,
                timeout=10
            )

            lines = result.stdout.split('\n')
            for line in lines:
                if 'LISTEN' in line:
                    for port in self.suspicious_ports:
                        if f':{port}' in line:
                            parts = line.split()
                            pid_prog = parts[-1] if parts else 'N/A'
                            self.findings.append({
                                'type': 'suspicious_port',
                                'port': port,
                                'local_address': parts[3] if len(parts) > 3 else 'N/A',
                                'pid_program': pid_prog
                            })
                            break

        except FileNotFoundError:
            print("[!] netstat not found. Trying ss...")
            try:
                result = subprocess.run(
                    ['ss', '-tlnp'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                lines = result.stdout.split('\n')
                for line in lines:
                    if 'LISTEN' in line:
                        for port in self.suspicious_ports:
                            if f':{port}' in line:
                                parts = line.split()
                                self.findings.append({
                                    'type': 'suspicious_port',
                                    'port': port,
                                    'local_address': parts[4] if len(parts) > 4 else 'N/A',
                                    'process': parts[-1] if parts else 'N/A'
                                })
                                break

            except Exception as e:
                print(f"[!] Error scanning ports: {e}")

        except Exception as e:
            print(f"[!] Error scanning ports: {e}")

    def scan_common_directories(self):
        """Scan common directories for LLM model files"""
        print("[*] Scanning common directories for model files...")

        common_dirs = [
            os.path.expanduser('~/.cache/huggingface'),
            os.path.expanduser('~/.cache/torch'),
            os.path.expanduser('~/.local/share/'),
            '/tmp',
            '/var/tmp',
            '/opt',
        ]

        for directory in common_dirs:
            if not os.path.exists(directory):
                continue

            try:
                # Search for files with model-related extensions
                for root, dirs, files in os.walk(directory):
                    # Limit depth to avoid excessive scanning
                    depth = root.replace(directory, '').count(os.sep)
                    if depth > 3:
                        continue

                    for file in files:
                        file_lower = file.lower()
                        for framework, signatures in self.file_signatures.items():
                            for sig in signatures:
                                if sig in file_lower:
                                    file_path = os.path.join(root, file)
                                    try:
                                        file_size = os.path.getsize(file_path)
                                        # Only report files larger than threshold (likely models)
                                        if file_size > self.MIN_MODEL_FILE_SIZE_MB * 1024 * 1024:
                                            self.findings.append({
                                                'type': 'model_file',
                                                'framework': framework,
                                                'path': file_path,
                                                'size_mb': file_size / (1024 * 1024)
                                            })
                                    except Exception:
                                        pass
                                    break

            except PermissionError:
                continue
            except Exception as e:
                continue

    def scan_system(self):
        """Perform complete signature-based scan"""
        print(f"[*] Starting signature-based detection at {datetime.now()}")
        print("-" * 80)

        self.scan_process_cmdlines()
        self.scan_environment_variables()
        self.scan_open_files()
        self.scan_listening_ports()
        self.scan_common_directories()

    def generate_report(self):
        """Generate detailed report of findings"""
        print("\n" + "=" * 80)
        print("SIGNATURE DETECTION REPORT")
        print("=" * 80)

        if not self.findings:
            print("[+] No LLM/AI signatures detected.")
            return

        # Group findings by type
        findings_by_type = {}
        for finding in self.findings:
            finding_type = finding['type']
            if finding_type not in findings_by_type:
                findings_by_type[finding_type] = []
            findings_by_type[finding_type].append(finding)

        # Report command signatures
        if 'command_signature' in findings_by_type:
            print(f"\n[!] Found {len(findings_by_type['command_signature'])} command signature(s):")
            for item in findings_by_type['command_signature']:
                print(f"    PID {item['pid']} ({item['user']})")
                print(f"    Pattern: {item['pattern']}")
                print(f"    Command: {item['command']}")
                print()

        # Report environment variables
        if 'environment_variable' in findings_by_type:
            print(f"\n[!] Found {len(findings_by_type['environment_variable'])} suspicious environment variable(s):")
            for item in findings_by_type['environment_variable']:
                print(f"    PID {item['pid']}")
                print(f"    Variable: {item['env_key']}")
                print(f"    Command: {item['cmdline']}")
                print()

        # Report open files
        if 'open_file_signature' in findings_by_type:
            print(f"\n[!] Found {len(findings_by_type['open_file_signature'])} open file signature(s):")
            for item in findings_by_type['open_file_signature']:
                print(f"    PID {item['pid']} ({item['user']}): {item['command']}")
                print(f"    Framework: {item['framework']}")
                print(f"    File: {item['file']}")
                print()

        # Report suspicious ports
        if 'suspicious_port' in findings_by_type:
            print(f"\n[!] Found {len(findings_by_type['suspicious_port'])} process(es) on suspicious ports:")
            for item in findings_by_type['suspicious_port']:
                print(f"    Port {item['port']}: {item['local_address']}")
                print(f"    Process: {item.get('pid_program', item.get('process', 'N/A'))}")
                print()

        # Report model files
        if 'model_file' in findings_by_type:
            print(f"\n[!] Found {len(findings_by_type['model_file'])} model file(s):")
            for item in findings_by_type['model_file'][:10]:  # Limit to first 10
                print(f"    Framework: {item['framework']}")
                print(f"    Path: {item['path']}")
                print(f"    Size: {item['size_mb']:.2f} MB")
                print()
            if len(findings_by_type['model_file']) > 10:
                print(f"    ... and {len(findings_by_type['model_file']) - 10} more")

        print("\n" + "=" * 80)

    def export_json(self, filename='signature_report.json'):
        """Export findings to JSON"""
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'findings': self.findings
        }

        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        print(f"[+] Report exported to {filename}")


def main():
    detector = SignatureDetector()
    detector.scan_system()
    detector.generate_report()
    detector.export_json()


if __name__ == '__main__':
    main()
