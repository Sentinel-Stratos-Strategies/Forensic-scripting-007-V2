#!/usr/bin/env python3
"""
Anomaly Detection Script for LLM/AI Process Detection
This script analyzes running processes for anomalous behavior patterns
that might indicate AI/LLM processes hiding in the system.
"""

import psutil
import re
import json
from collections import defaultdict
from datetime import datetime


class AnomalyDetector:
    def __init__(self):
        self.suspicious_patterns = []
        self.anomalies = defaultdict(list)

        # Common LLM/AI indicators
        self.llm_indicators = [
            'transformer', 'pytorch', 'tensorflow', 'huggingface',
            'llama', 'gpt', 'bert', 'model', 'inference',
            'tokenizer', 'embedding', 'neural', 'cuda', 'gpu'
        ]

        # Suspicious memory patterns (processes using >1GB)
        self.high_memory_threshold = 1024 * 1024 * 1024  # 1GB

        # Suspicious CPU patterns (processes using >50% CPU)
        self.high_cpu_threshold = 50.0

    def analyze_process_name(self, proc):
        """Analyze process name for LLM/AI indicators"""
        try:
            name = proc.name().lower()
            cmdline = ' '.join(proc.cmdline()).lower() if proc.cmdline() else ''

            for indicator in self.llm_indicators:
                if indicator in name or indicator in cmdline:
                    return {
                        'type': 'llm_indicator',
                        'indicator': indicator,
                        'name': proc.name(),
                        'cmdline': cmdline[:200],  # Limit output
                        'pid': proc.pid
                    }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        return None

    def analyze_resource_usage(self, proc):
        """Detect processes with unusually high resource usage"""
        anomalies = []
        try:
            # Check memory usage
            mem_info = proc.memory_info()
            if mem_info.rss > self.high_memory_threshold:
                anomalies.append({
                    'type': 'high_memory',
                    'pid': proc.pid,
                    'name': proc.name(),
                    'memory_mb': mem_info.rss / (1024 * 1024),
                    'memory_percent': proc.memory_percent()
                })

            # Check CPU usage
            cpu_percent = proc.cpu_percent(interval=0.1)
            if cpu_percent > self.high_cpu_threshold:
                anomalies.append({
                    'type': 'high_cpu',
                    'pid': proc.pid,
                    'name': proc.name(),
                    'cpu_percent': cpu_percent
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Expected during process scanning: processes may exit, become zombies,
            # or be inaccessible due to permissions. Skip and continue.
            pass

        return anomalies

    def analyze_network_connections(self, proc):
        """Detect suspicious network connections (API calls to LLM services)"""
        suspicious_domains = [
            'openai.com', 'anthropic.com', 'huggingface.co',
            'replicate.com', 'cohere.ai', 'ai21.com'
        ]

        try:
            connections = proc.connections(kind='inet')
            for conn in connections:
                if conn.raddr:
                    # Check for suspicious remote addresses
                    # Note: This is simplified; real forensics would do DNS resolution
                    return {
                        'type': 'network_connection',
                        'pid': proc.pid,
                        'name': proc.name(),
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'status': conn.status
                    }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process state can change during scanning (exit/permission/zombie); ignore and continue.
            pass

        return None

    def analyze_process_tree(self, proc):
        """Analyze parent-child relationships for suspicious patterns"""
        try:
            parent = proc.parent()
            children = proc.children()

            # Check for processes spawned by unusual parents
            if parent and parent.name().lower() in ['bash', 'sh', 'python', 'python3', 'node']:
                if any(indicator in proc.name().lower() for indicator in self.llm_indicators):
                    return {
                        'type': 'suspicious_parent',
                        'pid': proc.pid,
                        'name': proc.name(),
                        'parent_name': parent.name(),
                        'parent_pid': parent.pid
                    }

            # Check for processes with many children (possible worker pool)
            if len(children) > 10:
                return {
                    'type': 'many_children',
                    'pid': proc.pid,
                    'name': proc.name(),
                    'num_children': len(children)
                }

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        return None

    def scan_system(self):
        """Perform a complete system scan for anomalies"""
        print(f"[*] Starting anomaly detection scan at {datetime.now()}")
        print("[*] Scanning for LLM/AI processes and suspicious behavior...")
        print("-" * 80)

        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                # Check process name
                name_anomaly = self.analyze_process_name(proc)
                if name_anomaly:
                    self.anomalies['llm_indicators'].append(name_anomaly)

                # Check resource usage
                resource_anomalies = self.analyze_resource_usage(proc)
                for anomaly in resource_anomalies:
                    self.anomalies[anomaly['type']].append(anomaly)

                # Check network connections
                network_anomaly = self.analyze_network_connections(proc)
                if network_anomaly:
                    self.anomalies['network_connections'].append(network_anomaly)

                # Check process tree
                tree_anomaly = self.analyze_process_tree(proc)
                if tree_anomaly:
                    self.anomalies[tree_anomaly['type']].append(tree_anomaly)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def generate_report(self):
        """Generate a detailed report of findings"""
        print("\n" + "=" * 80)
        print("ANOMALY DETECTION REPORT")
        print("=" * 80)

        if not any(self.anomalies.values()):
            print("[+] No significant anomalies detected.")
            return

        # Report LLM indicators
        if self.anomalies['llm_indicators']:
            print(f"\n[!] Found {len(self.anomalies['llm_indicators'])} process(es) with LLM/AI indicators:")
            for item in self.anomalies['llm_indicators']:
                print(f"    PID {item['pid']}: {item['name']}")
                print(f"    Indicator: {item['indicator']}")
                print(f"    Command: {item['cmdline'][:100]}...")
                print()

        # Report high memory usage
        if self.anomalies['high_memory']:
            print(f"\n[!] Found {len(self.anomalies['high_memory'])} process(es) with high memory usage:")
            for item in self.anomalies['high_memory']:
                print(f"    PID {item['pid']}: {item['name']}")
                print(f"    Memory: {item['memory_mb']:.2f} MB ({item['memory_percent']:.2f}%)")
                print()

        # Report high CPU usage
        if self.anomalies['high_cpu']:
            print(f"\n[!] Found {len(self.anomalies['high_cpu'])} process(es) with high CPU usage:")
            for item in self.anomalies['high_cpu']:
                print(f"    PID {item['pid']}: {item['name']}")
                print(f"    CPU: {item['cpu_percent']:.2f}%")
                print()

        # Report network connections
        if self.anomalies['network_connections']:
            print(f"\n[!] Found {len(self.anomalies['network_connections'])} suspicious network connection(s):")
            for item in self.anomalies['network_connections']:
                print(f"    PID {item['pid']}: {item['name']}")
                print(f"    Remote: {item['remote_addr']} (Status: {item['status']})")
                print()

        # Report suspicious parent processes
        if self.anomalies['suspicious_parent']:
            print(f"\n[!] Found {len(self.anomalies['suspicious_parent'])} process(es) with suspicious parents:")
            for item in self.anomalies['suspicious_parent']:
                print(f"    PID {item['pid']}: {item['name']}")
                print(f"    Parent: {item['parent_name']} (PID {item['parent_pid']})")
                print()

        # Report processes with many children
        if self.anomalies['many_children']:
            print(f"\n[!] Found {len(self.anomalies['many_children'])} process(es) with many children:")
            for item in self.anomalies['many_children']:
                print(f"    PID {item['pid']}: {item['name']}")
                print(f"    Children: {item['num_children']}")
                print()

        print("\n" + "=" * 80)

    def export_json(self, filename='anomaly_report.json'):
        """Export findings to JSON file"""
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'anomalies': dict(self.anomalies)
        }

        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        print(f"[+] Report exported to {filename}")


def main():
    detector = AnomalyDetector()
    detector.scan_system()
    detector.generate_report()
    detector.export_json()


if __name__ == '__main__':
    main()
