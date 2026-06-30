#!/usr/bin/env python3
"""
Log Analysis Script for LLM/AI Detection and Log Manipulation Detection
This script analyzes system logs for signs of LLM activity and log tampering.
"""

import os
import re
import json
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path


class LogAnalyzer:
    # Configuration constants
    MAX_LOG_LINES_TO_SCAN = 10000  # Limit lines scanned per file for performance

    def __init__(self):
        self.findings = []

        # Log files to analyze
        self.log_files = [
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/auth.log',
            '/var/log/daemon.log',
            '/var/log/kern.log',
        ]

        # LLM/AI related patterns in logs
        self.llm_patterns = [
            r'cuda|gpu|nvidia',
            r'torch|pytorch|tensorflow',
            r'huggingface|transformers',
            r'model.*load|inference|prediction',
            r'api.*key|token.*auth',
            r'openai|anthropic|cohere',
        ]

        # Log manipulation indicators
        self.tampering_indicators = [
            r'log.*deleted|removed|cleared',
            r'journalctl.*clear|vacuum',
            r'rm.*\.log',
            r'truncate.*log',
            r'>/var/log/',  # Redirection to log files
        ]

    def check_log_integrity(self, log_file):
        """Check for signs of log tampering"""
        issues = []

        try:
            if not os.path.exists(log_file):
                return issues

            # Check file metadata
            stat_info = os.stat(log_file)
            mtime = datetime.fromtimestamp(stat_info.st_mtime)
            ctime = datetime.fromtimestamp(stat_info.st_ctime)

            # Check if log file was recently modified
            now = datetime.now()
            if (now - mtime).total_seconds() < 300:  # Modified in last 5 minutes
                issues.append({
                    'type': 'recent_modification',
                    'file': log_file,
                    'mtime': mtime.isoformat(),
                    'seconds_ago': (now - mtime).total_seconds()
                })

            # Check for suspicious file size
            if stat_info.st_size == 0:
                issues.append({
                    'type': 'empty_log',
                    'file': log_file,
                    'size': 0
                })

            # Check permissions
            mode = oct(stat_info.st_mode)[-3:]
            if mode == '777':
                issues.append({
                    'type': 'suspicious_permissions',
                    'file': log_file,
                    'permissions': mode
                })

        except PermissionError as e:
            issues.append({
                'type': 'integrity_check_permission_error',
                'file': log_file,
                'error': str(e)
            })
        except Exception as e:
            issues.append({
                'type': 'integrity_check_error',
                'file': log_file,
                'error_type': type(e).__name__,
                'error': str(e)
            })

        return issues

    def analyze_log_gaps(self, log_file):
        """Detect gaps in log timestamps (possible deletion)"""
        gaps = []

        try:
            if not os.path.exists(log_file):
                return gaps

            with open(log_file, 'r', errors='ignore') as f:
                lines = []
                for line in f:
                    lines.append(line)
                    if len(lines) >= 1000:
                        break

            # Parse timestamps and look for unusual gaps
            timestamps = []
            timestamp_patterns = [
                (r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})', 'iso'),  # ISO format
                (r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', 'syslog'),  # syslog format
            ]

            current_year = datetime.now().year

            for line in lines[:1000]:  # Sample first 1000 lines
                for pattern, fmt_type in timestamp_patterns:
                    match = re.search(pattern, line)
                    if match:
                        try:
                            ts_str = match.group(1)
                            parsed_ts = self._parse_timestamp(ts_str, fmt_type, current_year)
                            if parsed_ts:
                                timestamps.append(parsed_ts)
                            break
                        except Exception:
                            continue

            # Check for large gaps (>1 hour) between consecutive timestamps
            gap_threshold_seconds = 3600  # 1 hour
            for i in range(1, len(timestamps)):
                prev_ts = timestamps[i - 1]
                curr_ts = timestamps[i]
                gap_seconds = (curr_ts - prev_ts).total_seconds()

                # Only report positive gaps exceeding the threshold
                if gap_seconds > gap_threshold_seconds:
                    gaps.append({
                        'type': 'timestamp_analysis',
                        'file': log_file,
                        'start_time': prev_ts.isoformat(),
                        'end_time': curr_ts.isoformat(),
                        'gap_duration_seconds': gap_seconds,
                        'gap_duration_human': str(timedelta(seconds=int(gap_seconds)))
                    })

        except PermissionError:
            pass
        except Exception as e:
            pass

        return gaps

    def _parse_timestamp(self, ts_str, fmt_type, current_year):
        """Parse a timestamp string into a datetime object.

        Args:
            ts_str: The timestamp string to parse
            fmt_type: 'iso' for ISO format or 'syslog' for syslog format
            current_year: The year to use for syslog timestamps (which lack year)

        Returns:
            A datetime object or None if parsing fails
        """
        try:
            if fmt_type == 'iso':
                # Handle both space and 'T' separator
                ts_str_normalized = ts_str.replace('T', ' ')
                return datetime.strptime(ts_str_normalized, '%Y-%m-%d %H:%M:%S')
            elif fmt_type == 'syslog':
                # Syslog format: Mon DD HH:MM:SS (no year)
                # Normalize whitespace (may have variable spacing between month and day)
                ts_str_normalized = ' '.join(ts_str.split())
                parsed = datetime.strptime(ts_str_normalized, '%b %d %H:%M:%S')
                # Add current year since syslog format doesn't include it
                return parsed.replace(year=current_year)
        except ValueError:
            return None
        return None

    def search_llm_indicators(self, log_file):
        """Search for LLM/AI related entries in logs"""
        matches = []

        try:
            if not os.path.exists(log_file):
                return matches

            with open(log_file, 'r', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    for pattern in self.llm_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            matches.append({
                                'file': log_file,
                                'line': line_num,
                                'pattern': pattern,
                                'content': line.strip()[:200]
                            })
                            break

                    # Limit lines scanned for performance
                    if line_num > self.MAX_LOG_LINES_TO_SCAN:
                        break

        except PermissionError as e:
            self.findings.append({
                'type': 'scan_warning',
                'severity': 'low',
                'description': f'Permission denied while scanning {log_file}: {e}'
            })
        except Exception as e:
            self.findings.append({
                'type': 'scan_warning',
                'severity': 'low',
                'description': f'Error scanning {log_file} for LLM indicators: {e}'
            })

        return matches

    def search_tampering_commands(self, log_file):
        """Search for log tampering commands in bash history and logs"""
        tampering = []

        try:
            if not os.path.exists(log_file):
                return tampering

            with open(log_file, 'r', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    for pattern in self.tampering_indicators:
                        if re.search(pattern, line, re.IGNORECASE):
                            tampering.append({
                                'file': log_file,
                                'line': line_num,
                                'indicator': pattern,
                                'content': line.strip()[:200]
                            })
                            break

                    if line_num > self.MAX_LOG_LINES_TO_SCAN:
                        break

        except PermissionError as e:
            self.findings.append({
                'type': 'scan_warning',
                'severity': 'low',
                'description': f'Permission denied while scanning {log_file}: {e}'
            })
        except Exception as e:
            self.findings.append({
                'type': 'scan_warning',
                'severity': 'low',
                'description': f'Error scanning {log_file} for tampering indicators: {e}'
            })

        return tampering

    def analyze_bash_history(self):
        """Analyze bash history for suspicious commands"""
        history_files = [
            os.path.expanduser('~/.bash_history'),
            os.path.expanduser('~/.zsh_history'),
            '/root/.bash_history',
        ]

        suspicious_commands = []

        for history_file in history_files:
            try:
                if not os.path.exists(history_file):
                    continue

                with open(history_file, 'r', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        # Check for LLM indicators
                        for pattern in self.llm_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                suspicious_commands.append({
                                    'type': 'llm_command',
                                    'file': history_file,
                                    'line': line_num,
                                    'command': line.strip()[:200]
                                })
                                break

                        # Check for tampering
                        for pattern in self.tampering_indicators:
                            if re.search(pattern, line, re.IGNORECASE):
                                suspicious_commands.append({
                                    'type': 'tampering_command',
                                    'file': history_file,
                                    'line': line_num,
                                    'command': line.strip()[:200]
                                })
                                break

            except PermissionError:
                continue
            except Exception as e:
                continue

        return suspicious_commands

    def analyze_systemd_journal(self):
        """Analyze systemd journal for LLM activity"""
        import subprocess

        journal_findings = []

        try:
            # Search for LLM-related entries in journalctl
            for pattern in ['cuda', 'gpu', 'torch', 'model', 'inference']:
                result = subprocess.run(
                    ['journalctl', '--since', '24 hours ago', '-g', pattern, '-n', '10'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 0:
                        journal_findings.append({
                            'pattern': pattern,
                            'match_count': len(lines),
                            'sample': lines[0][:200] if lines else ''
                        })

        except FileNotFoundError:
            pass  # journalctl not available
        except Exception as e:
            pass

        return journal_findings

    def scan_system(self):
        """Perform complete log analysis"""
        print(f"[*] Starting log analysis at {datetime.now()}")
        print("-" * 80)

        # Check log integrity
        print("[*] Checking log file integrity...")
        for log_file in self.log_files:
            integrity_issues = self.check_log_integrity(log_file)
            if integrity_issues:
                self.findings.extend(integrity_issues)

            gaps = self.analyze_log_gaps(log_file)
            if gaps:
                self.findings.extend(gaps)

        # Search for LLM indicators
        print("[*] Searching for LLM/AI indicators in logs...")
        for log_file in self.log_files:
            matches = self.search_llm_indicators(log_file)
            if matches:
                for match in matches:
                    self.findings.append({
                        'type': 'llm_indicator',
                        **match
                    })

        # Search for tampering
        print("[*] Searching for log tampering indicators...")
        for log_file in self.log_files:
            tampering = self.search_tampering_commands(log_file)
            if tampering:
                for item in tampering:
                    self.findings.append({
                        'type': 'tampering_indicator',
                        **item
                    })

        # Analyze bash history
        print("[*] Analyzing command history...")
        history_findings = self.analyze_bash_history()
        self.findings.extend(history_findings)

        # Analyze systemd journal
        print("[*] Analyzing systemd journal...")
        journal_findings = self.analyze_systemd_journal()
        for finding in journal_findings:
            self.findings.append({
                'type': 'journal_entry',
                **finding
            })

    def generate_report(self):
        """Generate detailed report"""
        print("\n" + "=" * 80)
        print("LOG ANALYSIS REPORT")
        print("=" * 80)

        if not self.findings:
            print("[+] No suspicious log entries or tampering detected.")
            print("[*] Note: Some log files may require elevated privileges")
            return

        # Group by type
        findings_by_type = defaultdict(list)
        for finding in self.findings:
            finding_type = finding.get('type', 'unknown')
            findings_by_type[finding_type].append(finding)

        # Report integrity issues
        if findings_by_type['recent_modification']:
            print(f"\n[!] Found {len(findings_by_type['recent_modification'])} recently modified log file(s):")
            for item in findings_by_type['recent_modification']:
                print(f"    File: {item['file']}")
                print(f"    Modified: {item['seconds_ago']:.0f} seconds ago")
                print()

        if findings_by_type['empty_log']:
            print(f"\n[!] Found {len(findings_by_type['empty_log'])} empty log file(s):")
            for item in findings_by_type['empty_log']:
                print(f"    File: {item['file']}")
                print()

        if findings_by_type['suspicious_permissions']:
            print(f"\n[!] Found {len(findings_by_type['suspicious_permissions'])} file(s) with suspicious permissions:")
            for item in findings_by_type['suspicious_permissions']:
                print(f"    File: {item['file']}")
                print(f"    Permissions: {item['permissions']}")
                print()

        # Report LLM indicators
        if findings_by_type['llm_indicator']:
            print(f"\n[!] Found {len(findings_by_type['llm_indicator'])} LLM/AI indicator(s) in logs:")
            for item in findings_by_type['llm_indicator'][:10]:
                print(f"    File: {item['file']}:{item['line']}")
                print(f"    Pattern: {item['pattern']}")
                print(f"    Content: {item['content'][:100]}")
                print()
            if len(findings_by_type['llm_indicator']) > 10:
                print(f"    ... and {len(findings_by_type['llm_indicator']) - 10} more")

        # Report tampering
        if findings_by_type['tampering_indicator']:
            print(f"\n[!] Found {len(findings_by_type['tampering_indicator'])} tampering indicator(s):")
            for item in findings_by_type['tampering_indicator'][:10]:
                print(f"    File: {item['file']}:{item['line']}")
                print(f"    Indicator: {item['indicator']}")
                print(f"    Content: {item['content'][:100]}")
                print()

        # Report command history
        if findings_by_type['llm_command']:
            print(f"\n[!] Found {len(findings_by_type['llm_command'])} LLM-related command(s) in history:")
            for item in findings_by_type['llm_command'][:10]:
                print(f"    File: {item['file']}")
                print(f"    Command: {item['command'][:100]}")
                print()

        if findings_by_type['tampering_command']:
            print(f"\n[!] Found {len(findings_by_type['tampering_command'])} tampering command(s) in history:")
            for item in findings_by_type['tampering_command'][:10]:
                print(f"    File: {item['file']}")
                print(f"    Command: {item['command'][:100]}")
                print()

        # Report journal findings
        if findings_by_type['journal_entry']:
            print(f"\n[!] Found {len(findings_by_type['journal_entry'])} journal match(es):")
            for item in findings_by_type['journal_entry'][:5]:
                print(f"    Pattern: {item['pattern']}")
                print(f"    Matches: {item['match_count']}")
                print()

        if findings_by_type['timestamp_analysis']:
            print(f"\n[!] Found {len(findings_by_type['timestamp_analysis'])} timestamp gap(s) exceeding 1 hour:")
            for item in findings_by_type['timestamp_analysis'][:10]:
                print(f"    File: {item['file']}")
                print(f"    Gap start: {item['start_time']}")
                print(f"    Gap end: {item['end_time']}")
                print(f"    Duration: {item['gap_duration_human']} ({item['gap_duration_seconds']:.0f} seconds)")
                print()

        print("\n" + "=" * 80)

    def export_json(self, filename='log_analysis_report.json'):
        """Export findings to JSON"""
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'findings': self.findings
        }

        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        print(f"[+] Report exported to {filename}")


def main():
    analyzer = LogAnalyzer()
    analyzer.scan_system()
    analyzer.generate_report()
    analyzer.export_json()


if __name__ == '__main__':
    main()
