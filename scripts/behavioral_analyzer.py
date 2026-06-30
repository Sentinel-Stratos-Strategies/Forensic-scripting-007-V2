#!/usr/bin/env python3
"""
Behavioral Analysis Script for LLM/AI Process Detection
This script monitors system calls and process behavior patterns to detect
anomalous behavior typical of LLM/AI inference processes.
"""

import subprocess
import time
import re
import json
from datetime import datetime
from collections import defaultdict


class BehavioralAnalyzer:
    # Configuration constants
    LARGE_MEMORY_THRESHOLD_MB = 100  # MB - threshold for large anonymous memory regions
    HIGH_THREAD_COUNT_THRESHOLD = 10  # Number of threads indicating parallel processing
    SYSCALL_COUNT_THRESHOLD = 100  # Minimum syscall count to be considered suspicious

    def __init__(self, duration=60):
        self.duration = duration
        self.behavior_data = defaultdict(lambda: defaultdict(int))
        self.suspicious_behaviors = []

        # Behavioral patterns to watch for
        self.suspicious_syscalls = [
            'mmap',  # Memory mapping (model loading)
            'mprotect',  # Memory protection changes
            'brk',  # Heap expansion
            'futex',  # Thread synchronization (parallel inference)
            'sched_setaffinity',  # CPU affinity changes
            'openat',  # File operations (model loading)
        ]

        # File access patterns
        self.suspicious_file_patterns = [
            r'\.pt', r'\.pth', r'\.pb', r'\.h5', r'\.onnx',
            r'model', r'checkpoint', r'config\.json', r'tokenizer'
        ]

    def monitor_strace_process(self, pid, duration=10):
        """Monitor a specific process using strace"""
        print(f"[*] Monitoring process {pid} for {duration} seconds...")

        try:
            # Run strace on the process
            cmd = ['strace', '-c', '-p', str(pid)]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Let it run for the specified duration
            time.sleep(duration)
            process.terminate()

            stdout, stderr = process.communicate(timeout=5)

            # Parse strace output
            syscall_counts = {}
            lines = stderr.split('\n')

            for line in lines:
                # Look for syscall statistics
                parts = line.split()
                if len(parts) >= 6 and parts[0].replace('.', '').isdigit():
                    syscall_name = parts[5]
                    try:
                        count = int(parts[3])
                        syscall_counts[syscall_name] = count
                    except (ValueError, IndexError):
                        continue

            return syscall_counts

        except subprocess.TimeoutExpired:
            process.kill()
            return {}
        except PermissionError:
            print(f"[!] Permission denied for PID {pid}. Try running with sudo.")
            return {}
        except Exception as e:
            print(f"[!] Error monitoring process {pid}: {e}")
            return {}

    def analyze_syscall_patterns(self, pid, syscall_counts):
        """Analyze system call patterns for anomalies"""
        suspicious_count = 0
        details = []

        for syscall in self.suspicious_syscalls:
            if syscall in syscall_counts:
                count = syscall_counts[syscall]
                if count > self.SYSCALL_COUNT_THRESHOLD:  # Threshold for suspicious activity
                    suspicious_count += 1
                    details.append(f"{syscall}: {count} calls")

        if suspicious_count >= 2:  # Multiple suspicious syscalls
            return {
                'pid': pid,
                'suspicious_syscalls': suspicious_count,
                'details': details,
                'all_syscalls': syscall_counts
            }

        return None

    def monitor_file_access(self, pid, duration=10):
        """Monitor file access patterns"""
        print(f"[*] Monitoring file access for process {pid}...")

        try:
            # Use strace to monitor file operations
            cmd = ['strace', '-e', 'trace=open,openat,read,write', '-p', str(pid)]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            time.sleep(duration)
            process.terminate()

            stdout, stderr = process.communicate(timeout=5)

            # Look for suspicious file patterns
            suspicious_files = []
            lines = stderr.split('\n')

            for line in lines:
                for pattern in self.suspicious_file_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        suspicious_files.append(line.strip())
                        break

            return suspicious_files

        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            return []
        except Exception as e:
            print(f"[!] Error monitoring file access: {e}")
            return []

    def analyze_memory_behavior(self, pid):
        """Analyze memory allocation behavior"""
        print(f"[*] Analyzing memory behavior for process {pid}...")

        try:
            # Check /proc/<pid>/maps for memory regions
            with open(f'/proc/{pid}/maps', 'r') as f:
                maps = f.readlines()

            large_anon_regions = 0
            total_anon_size = 0

            for line in maps:
                if '[anon]' in line or 'anon_inode' in line:
                    parts = line.split()
                    if parts:
                        addr_range = parts[0].split('-')
                        if len(addr_range) == 2:
                            start = int(addr_range[0], 16)
                            end = int(addr_range[1], 16)
                            size = end - start

                            # Check for large anonymous regions
                            if size > self.LARGE_MEMORY_THRESHOLD_MB * 1024 * 1024:
                                large_anon_regions += 1
                                total_anon_size += size

            if large_anon_regions > 0:
                return {
                    'pid': pid,
                    'large_anon_regions': large_anon_regions,
                    'total_anon_size_mb': total_anon_size / (1024 * 1024)
                }

        except FileNotFoundError:
            print(f"[!] Process {pid} no longer exists")
        except PermissionError:
            print(f"[!] Permission denied for process {pid}")
        except Exception as e:
            print(f"[!] Error analyzing memory: {e}")

        return None

    def analyze_thread_behavior(self, pid):
        """Analyze thread creation patterns"""
        try:
            # Count threads in process
            with open(f'/proc/{pid}/status', 'r') as f:
                status = f.read()

            thread_match = re.search(r'Threads:\s+(\d+)', status)
            if thread_match:
                thread_count = int(thread_match.group(1))

                # Check for high thread count (parallel inference)
                if thread_count > self.HIGH_THREAD_COUNT_THRESHOLD:
                    return {
                        'pid': pid,
                        'thread_count': thread_count
                    }

        except Exception as e:
            print(f"[!] Error analyzing threads: {e}")

        return None

    def get_suspicious_processes(self):
        """Get list of potentially suspicious processes to monitor"""
        suspicious_pids = []

        try:
            result = subprocess.run(
                ['ps', 'aux', '--sort=-%mem'],
                capture_output=True,
                text=True,
                timeout=10
            )

            lines = result.stdout.split('\n')[1:11]  # Top 10 by memory

            for line in lines:
                if line.strip():
                    parts = line.split(None, 10)
                    if len(parts) >= 2:
                        pid = parts[1]
                        try:
                            suspicious_pids.append(int(pid))
                        except ValueError:
                            continue

        except Exception as e:
            print(f"[!] Error getting process list: {e}")

        return suspicious_pids

    def scan_system(self):
        """Perform behavioral analysis scan"""
        print(f"[*] Starting behavioral analysis at {datetime.now()}")
        print(f"[*] Monitoring duration: {self.duration} seconds per process")
        print("-" * 80)

        # Get suspicious processes
        pids = self.get_suspicious_processes()

        if not pids:
            print("[!] No processes to monitor")
            return

        print(f"[*] Monitoring {len(pids)} high-memory processes...")

        for pid in pids[:5]:  # Monitor top 5 to keep scan time reasonable
            try:
                print(f"\n[*] Analyzing PID {pid}...")

                # Analyze memory behavior
                mem_behavior = self.analyze_memory_behavior(pid)
                if mem_behavior:
                    self.suspicious_behaviors.append({
                        'type': 'memory_behavior',
                        **mem_behavior
                    })

                # Analyze thread behavior
                thread_behavior = self.analyze_thread_behavior(pid)
                if thread_behavior:
                    self.suspicious_behaviors.append({
                        'type': 'thread_behavior',
                        **thread_behavior
                    })

                # Monitor syscalls (requires root)
                syscall_counts = self.monitor_strace_process(pid, duration=self.duration)
                if syscall_counts:
                    syscall_analysis = self.analyze_syscall_patterns(pid, syscall_counts)
                    if syscall_analysis:
                        self.suspicious_behaviors.append({
                            'type': 'syscall_behavior',
                            **syscall_analysis
                        })

                # Monitor file access (requires root)
                suspicious_files = self.monitor_file_access(pid, duration=self.duration)
                if suspicious_files:
                    self.suspicious_behaviors.append({
                        'type': 'file_access',
                        'pid': pid,
                        'suspicious_files': suspicious_files[:10]  # Limit output
                    })

            except Exception as e:
                print(f"[!] Error analyzing PID {pid}: {e}")
                continue

    def generate_report(self):
        """Generate detailed report"""
        print("\n" + "=" * 80)
        print("BEHAVIORAL ANALYSIS REPORT")
        print("=" * 80)

        if not self.suspicious_behaviors:
            print("[+] No suspicious behavioral patterns detected.")
            print("[*] Note: Some checks require root privileges (strace)")
            return

        # Group by type
        behaviors_by_type = defaultdict(list)
        for behavior in self.suspicious_behaviors:
            behaviors_by_type[behavior['type']].append(behavior)

        # Report memory behavior
        if behaviors_by_type['memory_behavior']:
            print(f"\n[!] Found {len(behaviors_by_type['memory_behavior'])} process(es) with suspicious memory behavior:")
            for item in behaviors_by_type['memory_behavior']:
                print(f"    PID {item['pid']}")
                print(f"    Large anonymous regions: {item['large_anon_regions']}")
                print(f"    Total size: {item['total_anon_size_mb']:.2f} MB")
                print()

        # Report thread behavior
        if behaviors_by_type['thread_behavior']:
            print(f"\n[!] Found {len(behaviors_by_type['thread_behavior'])} process(es) with high thread count:")
            for item in behaviors_by_type['thread_behavior']:
                print(f"    PID {item['pid']}")
                print(f"    Threads: {item['thread_count']}")
                print()

        # Report syscall behavior
        if behaviors_by_type['syscall_behavior']:
            print(f"\n[!] Found {len(behaviors_by_type['syscall_behavior'])} process(es) with suspicious syscall patterns:")
            for item in behaviors_by_type['syscall_behavior']:
                print(f"    PID {item['pid']}")
                print(f"    Suspicious syscalls: {item['suspicious_syscalls']}")
                print(f"    Details: {', '.join(item['details'])}")
                print()

        # Report file access
        if behaviors_by_type['file_access']:
            print(f"\n[!] Found {len(behaviors_by_type['file_access'])} process(es) with suspicious file access:")
            for item in behaviors_by_type['file_access']:
                print(f"    PID {item['pid']}")
                print(f"    Suspicious file operations:")
                for file_op in item['suspicious_files'][:5]:
                    print(f"      {file_op}")
                print()

        print("\n" + "=" * 80)

    def export_json(self, filename='behavioral_report.json'):
        """Export findings to JSON"""
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'duration': self.duration,
            'behaviors': self.suspicious_behaviors
        }

        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        print(f"[+] Report exported to {filename}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Behavioral Analysis for LLM/AI Detection')
    parser.add_argument('-d', '--duration', type=int, default=10,
                        help='Monitoring duration per process in seconds (default: 10)')
    args = parser.parse_args()

    analyzer = BehavioralAnalyzer(duration=args.duration)
    analyzer.scan_system()
    analyzer.generate_report()
    analyzer.export_json()


if __name__ == '__main__':
    main()
