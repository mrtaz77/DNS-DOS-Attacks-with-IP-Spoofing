#!/usr/bin/env python3
"""
DNS Attack Metrics Analyzer
Analyzes DNS server logs to extract security and performance metrics for presentation
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Any

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from matplotlib.dates import DateFormatter
import matplotlib.dates as mdates

class DNSMetricsAnalyzer:
    def __init__(self, log_file: str, output_dir: str = "simulation/server"):
        self.log_file = log_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize metrics storage
        self.metrics = {
            'total_requests': 0,
            'nxdomain_responses': 0,
            'cache_hits': 0,
            'forwarded_queries': 0,
            'unique_clients': set(),
            'query_types': Counter(),
            'queried_domains': Counter(),
            'attack_patterns': defaultdict(int),
            'response_times': [],
            'requests_per_second': defaultdict(int),
            'hourly_distribution': defaultdict(int),
            'client_behavior': defaultdict(lambda: {'requests': 0, 'nxdomain': 0, 'last_seen': None}),
            'suspicious_activity': [],
            'error_rates': defaultdict(int),
            'cache_performance': {'hits': 0, 'misses': 0, 'hit_rate': 0}
        }
        
        # Attack detection patterns
        self.attack_patterns = {
            'subdomain_flood': re.compile(r'[a-z0-9]{20,}\.'),  # Long random subdomains
            'amplification': re.compile(r'\bANY\b|\bTXT\b'),     # Large response queries
            'nxdomain_flood': re.compile(r'NXDOMAIN'),           # Non-existent domains
        }
    
    def parse_logs(self):
        """Parse DNS server logs and extract metrics"""
        print(f"Parsing logs from {self.log_file}...")
        
        with open(self.log_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                if line_num % 10000 == 0:
                    print(f"Processed {line_num} log lines...")
                
                self._parse_log_line(line.strip())
        
        self._calculate_derived_metrics()
        print(f"Log parsing complete. Processed {line_num} lines.")
    
    def _parse_log_line(self, line: str):
        """Parse individual log line and extract relevant information"""
        if not line:
            return
        
        # Extract timestamp
        timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
        if not timestamp_match:
            return
        
        timestamp_str = timestamp_match.group(1)
        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        hour_key = timestamp.strftime('%Y-%m-%d %H:00:00')
        second_key = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        
        # Count requests per second and hourly distribution
        self.metrics['requests_per_second'][second_key] += 1
        self.metrics['hourly_distribution'][hour_key] += 1
        
        # Parse different log patterns
        if 'Received request from' in line:
            self._parse_request(line, timestamp)
        elif 'NXDOMAIN' in line:
            self._parse_nxdomain(line, timestamp)
        elif 'Cache hit' in line:
            self._parse_cache_hit(line, timestamp)
        elif 'Forwarding query' in line:
            self._parse_forwarded_query(line, timestamp)
        elif 'Answered query' in line:
            self._parse_answered_query(line, timestamp)
    
    def _parse_request(self, line: str, timestamp: datetime):
        """Parse incoming request log entry"""
        self.metrics['total_requests'] += 1
        
        # Extract client IP
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            client_ip = ip_match.group(1)
            self.metrics['unique_clients'].add(client_ip)
            self.metrics['client_behavior'][client_ip]['requests'] += 1
            self.metrics['client_behavior'][client_ip]['last_seen'] = timestamp
    
    def _parse_nxdomain(self, line: str, timestamp: datetime):
        """Parse NXDOMAIN response"""
        self.metrics['nxdomain_responses'] += 1
        
        # Extract domain for NXDOMAIN analysis
        domain_match = re.search(r'for ([^\s]+)\s+[A-Z]+', line)
        if domain_match:
            domain = domain_match.group(1)
            self.metrics['queried_domains'][domain] += 1
            
            # Check for attack patterns
            if self.attack_patterns['subdomain_flood'].search(domain):
                self.metrics['attack_patterns']['subdomain_flood'] += 1
            
        # Track client NXDOMAIN behavior
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            client_ip = ip_match.group(1)
            self.metrics['client_behavior'][client_ip]['nxdomain'] += 1
    
    def _parse_cache_hit(self, line: str, timestamp: datetime):
        """Parse cache hit entry"""
        self.metrics['cache_hits'] += 1
        self.metrics['cache_performance']['hits'] += 1
        
        # Extract query details
        query_match = re.search(r'for ([^\s]+)\s+([A-Z]+)', line)
        if query_match:
            domain, qtype = query_match.groups()
            self.metrics['queried_domains'][domain] += 1
            self.metrics['query_types'][qtype] += 1
    
    def _parse_forwarded_query(self, line: str, timestamp: datetime):
        """Parse forwarded query entry"""
        self.metrics['forwarded_queries'] += 1
        self.metrics['cache_performance']['misses'] += 1
        
        # Extract query details
        query_match = re.search(r'query ([^\s]+)\s+([A-Z]+)', line)
        if query_match:
            domain, qtype = query_match.groups()
            self.metrics['queried_domains'][domain] += 1
            self.metrics['query_types'][qtype] += 1
            
            # Check for amplification attacks
            if qtype in ['ANY', 'TXT']:
                self.metrics['attack_patterns']['amplification'] += 1
    
    def _parse_answered_query(self, line: str, timestamp: datetime):
        """Parse answered query entry"""
        # Extract query details for statistics
        query_match = re.search(r'for ([^\s]+)\s+([A-Z]+)', line)
        if query_match:
            domain, qtype = query_match.groups()
            self.metrics['queried_domains'][domain] += 1
            self.metrics['query_types'][qtype] += 1
    
    def _calculate_derived_metrics(self):
        """Calculate derived metrics from raw data"""
        # Cache hit rate
        total_cache_ops = self.metrics['cache_performance']['hits'] + self.metrics['cache_performance']['misses']
        if total_cache_ops > 0:
            self.metrics['cache_performance']['hit_rate'] = (
                self.metrics['cache_performance']['hits'] / total_cache_ops * 100
            )
        
        # Identify suspicious clients
        for client_ip, behavior in self.metrics['client_behavior'].items():
            if behavior['requests'] > 0:
                nxdomain_rate = behavior['nxdomain'] / behavior['requests']
                if nxdomain_rate > 0.8 and behavior['requests'] > 100:  # High NXDOMAIN rate + high volume
                    self.metrics['suspicious_activity'].append({
                        'client': client_ip,
                        'requests': behavior['requests'],
                        'nxdomain_rate': nxdomain_rate,
                        'type': 'potential_attack'
                    })
        
        # Convert sets to counts for JSON serialization
        self.metrics['unique_clients'] = len(self.metrics['unique_clients'])
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive metrics report"""
        report = {
            'summary': {
                'total_requests': self.metrics['total_requests'],
                'unique_clients': self.metrics['unique_clients'],
                'nxdomain_responses': self.metrics['nxdomain_responses'],
                'nxdomain_rate': round(self.metrics['nxdomain_responses'] / max(self.metrics['total_requests'], 1) * 100, 2),
                'cache_hits': self.metrics['cache_hits'],
                'cache_hit_rate': round(self.metrics['cache_performance']['hit_rate'], 2),
                'forwarded_queries': self.metrics['forwarded_queries'],
            },
            'attack_analysis': {
                'suspected_attacks': dict(self.metrics['attack_patterns']),
                'suspicious_clients': len(self.metrics['suspicious_activity']),
                'top_suspicious_clients': self.metrics['suspicious_activity'][:10]
            },
            'query_analysis': {
                'top_domains': dict(self.metrics['queried_domains'].most_common(20)),
                'query_types': dict(self.metrics['query_types']),
                'total_unique_domains': len(self.metrics['queried_domains'])
            },
            'performance_metrics': {
                'peak_qps': max(self.metrics['requests_per_second'].values()) if self.metrics['requests_per_second'] else 0,
                'avg_qps': round(sum(self.metrics['requests_per_second'].values()) / max(len(self.metrics['requests_per_second']), 1), 2),
                'busiest_hour': max(self.metrics['hourly_distribution'].items(), key=lambda x: x[1]) if self.metrics['hourly_distribution'] else ('N/A', 0)
            }
        }
        
        return report
    
    def create_visualizations(self):
        """Create comprehensive visualizations"""
        print("Generating visualizations...")
        
        # Set style for better-looking plots
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
        # Create multiple visualization plots
        self._plot_requests_over_time()
        self._plot_query_type_distribution()
        self._plot_top_domains()
        self._plot_attack_patterns()
        self._plot_client_behavior()
        self._plot_performance_metrics()
        self._plot_nxdomain_analysis()
        self._create_summary_dashboard()
        
        print(f"Visualizations saved to {self.output_dir}/")
    
    def _plot_requests_over_time(self):
        """Plot DNS requests over time"""
        if not self.metrics['hourly_distribution']:
            return
        
        # Convert to DataFrame for easier plotting
        times = []
        counts = []
        for time_str, count in sorted(self.metrics['hourly_distribution'].items()):
            times.append(datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S'))
            counts.append(count)
        
        df = pd.DataFrame({'time': times, 'requests': counts})
        
        plt.figure(figsize=(15, 8))
        plt.subplot(2, 1, 1)
        plt.plot(df['time'], df['requests'], linewidth=2, color='blue')
        plt.title('DNS Requests Over Time (Hourly)', fontsize=16, fontweight='bold')
        plt.xlabel('Time')
        plt.ylabel('Requests per Hour')
        plt.grid(True, alpha=0.3)
        plt.xticks(rotation=45)
        
        # QPS over time (if we have second-level data)
        if self.metrics['requests_per_second']:
            plt.subplot(2, 1, 2)
            qps_times = []
            qps_values = []
            for time_str, count in sorted(self.metrics['requests_per_second'].items()):
                qps_times.append(datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S'))
                qps_values.append(count)
            
            # Sample data if too many points
            if len(qps_times) > 1000:
                step = len(qps_times) // 1000
                qps_times = qps_times[::step]
                qps_values = qps_values[::step]
            
            plt.plot(qps_times, qps_values, linewidth=1, color='red', alpha=0.7)
            plt.title('Queries Per Second', fontsize=14, fontweight='bold')
            plt.xlabel('Time')
            plt.ylabel('QPS')
            plt.grid(True, alpha=0.3)
            plt.xticks(rotation=45)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'requests_over_time.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_query_type_distribution(self):
        """Plot distribution of DNS query types"""
        if not self.metrics['query_types']:
            return
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Pie chart
        query_types = dict(self.metrics['query_types'].most_common(10))
        ax1.pie(query_types.values(), labels=query_types.keys(), autopct='%1.1f%%', startangle=90)
        ax1.set_title('Query Type Distribution', fontsize=14, fontweight='bold')
        
        # Bar chart
        ax2.bar(query_types.keys(), query_types.values(), color='skyblue')
        ax2.set_title('Query Type Counts', fontsize=14, fontweight='bold')
        ax2.set_xlabel('Query Type')
        ax2.set_ylabel('Count')
        ax2.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'query_type_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_top_domains(self):
        """Plot most queried domains"""
        if not self.metrics['queried_domains']:
            return
        
        top_domains = dict(self.metrics['queried_domains'].most_common(20))
        
        plt.figure(figsize=(12, 8))
        plt.barh(range(len(top_domains)), list(top_domains.values()), color='lightcoral')
        plt.yticks(range(len(top_domains)), list(top_domains.keys()))
        plt.xlabel('Query Count')
        plt.title('Top 20 Queried Domains', fontsize=16, fontweight='bold')
        plt.grid(axis='x', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'top_queried_domains.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_attack_patterns(self):
        """Plot detected attack patterns"""
        if not self.metrics['attack_patterns']:
            return
        
        attack_data = dict(self.metrics['attack_patterns'])
        
        plt.figure(figsize=(10, 6))
        bars = plt.bar(attack_data.keys(), attack_data.values(), color=['red', 'orange', 'yellow'])
        plt.title('Detected Attack Patterns', fontsize=16, fontweight='bold')
        plt.xlabel('Attack Type')
        plt.ylabel('Detected Count')
        plt.xticks(rotation=45)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}', ha='center', va='bottom')
        
        plt.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        plt.savefig(self.output_dir / 'attack_patterns.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_client_behavior(self):
        """Analyze and plot client behavior patterns"""
        if not self.metrics['client_behavior']:
            return
        
        # Prepare data for analysis
        client_requests = []
        client_nxdomain_rates = []
        client_ips = []
        
        for ip, behavior in self.metrics['client_behavior'].items():
            if behavior['requests'] > 10:  # Only consider clients with significant activity
                client_requests.append(behavior['requests'])
                nxdomain_rate = behavior['nxdomain'] / behavior['requests'] if behavior['requests'] > 0 else 0
                client_nxdomain_rates.append(nxdomain_rate * 100)
                client_ips.append(ip)
        
        if not client_requests:
            return
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        
        # Scatter plot: Requests vs NXDOMAIN rate
        ax1.scatter(client_requests, client_nxdomain_rates, alpha=0.6, color='blue')
        ax1.set_xlabel('Total Requests')
        ax1.set_ylabel('NXDOMAIN Rate (%)')
        ax1.set_title('Client Request Volume vs NXDOMAIN Rate')
        ax1.grid(True, alpha=0.3)
        
        # Histogram of request counts
        ax2.hist(client_requests, bins=20, color='green', alpha=0.7)
        ax2.set_xlabel('Requests per Client')
        ax2.set_ylabel('Number of Clients')
        ax2.set_title('Distribution of Client Request Volumes')
        ax2.grid(axis='y', alpha=0.3)
        
        # Histogram of NXDOMAIN rates
        ax3.hist(client_nxdomain_rates, bins=20, color='orange', alpha=0.7)
        ax3.set_xlabel('NXDOMAIN Rate (%)')
        ax3.set_ylabel('Number of Clients')
        ax3.set_title('Distribution of Client NXDOMAIN Rates')
        ax3.grid(axis='y', alpha=0.3)
        
        # Top clients by request volume
        top_clients = sorted(zip(client_ips, client_requests), key=lambda x: x[1], reverse=True)[:10]
        if top_clients:
            ips, requests = zip(*top_clients)
            ax4.barh(range(len(ips)), requests, color='red')
            ax4.set_yticks(range(len(ips)))
            ax4.set_yticklabels(ips)
            ax4.set_xlabel('Total Requests')
            ax4.set_title('Top 10 Clients by Request Volume')
            ax4.grid(axis='x', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'client_behavior_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_performance_metrics(self):
        """Plot server performance metrics"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        
        # Cache performance
        cache_labels = ['Cache Hits', 'Cache Misses']
        cache_values = [self.metrics['cache_performance']['hits'], self.metrics['cache_performance']['misses']]
        ax1.pie(cache_values, labels=cache_labels, autopct='%1.1f%%', colors=['green', 'red'])
        ax1.set_title(f'Cache Performance (Hit Rate: {self.metrics["cache_performance"]["hit_rate"]:.1f}%)')
        
        # Response type distribution
        response_types = {
            'Successful': self.metrics['total_requests'] - self.metrics['nxdomain_responses'],
            'NXDOMAIN': self.metrics['nxdomain_responses']
        }
        ax2.bar(response_types.keys(), response_types.values(), color=['blue', 'red'])
        ax2.set_title('Response Type Distribution')
        ax2.set_ylabel('Count')
        
        # QPS distribution (if available)
        if self.metrics['requests_per_second']:
            qps_values = list(self.metrics['requests_per_second'].values())
            ax3.hist(qps_values, bins=30, color='purple', alpha=0.7)
            ax3.set_xlabel('Queries Per Second')
            ax3.set_ylabel('Frequency')
            ax3.set_title('QPS Distribution')
            ax3.grid(axis='y', alpha=0.3)
        
        # Summary metrics
        summary_data = {
            'Total Requests': self.metrics['total_requests'],
            'Unique Clients': self.metrics['unique_clients'],
            'Cache Hits': self.metrics['cache_hits'],
            'Forwarded': self.metrics['forwarded_queries']
        }
        ax4.bar(summary_data.keys(), summary_data.values(), color='skyblue')
        ax4.set_title('Summary Metrics')
        ax4.set_ylabel('Count')
        ax4.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'performance_metrics.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_nxdomain_analysis(self):
        """Detailed analysis of NXDOMAIN responses"""
        plt.figure(figsize=(12, 8))
        
        # Calculate NXDOMAIN rate over time
        nxdomain_hourly = defaultdict(int)
        total_hourly = defaultdict(int)
        
        # This is a simplified version - in a real implementation, you'd track NXDOMAIN per hour
        for hour, requests in self.metrics['hourly_distribution'].items():
            total_hourly[hour] = requests
            # Estimate NXDOMAIN based on overall rate
            nxdomain_rate = self.metrics['nxdomain_responses'] / max(self.metrics['total_requests'], 1)
            nxdomain_hourly[hour] = int(requests * nxdomain_rate)
        
        if total_hourly:
            hours = sorted(total_hourly.keys())
            nxdomain_counts = [nxdomain_hourly[h] for h in hours]
            total_counts = [total_hourly[h] for h in hours]
            rates = [n/max(t, 1)*100 for n, t in zip(nxdomain_counts, total_counts)]
            
            times = [datetime.strptime(h, '%Y-%m-%d %H:%M:%S') for h in hours]
            
            plt.subplot(2, 1, 1)
            plt.plot(times, nxdomain_counts, 'r-', label='NXDOMAIN Count', linewidth=2)
            plt.plot(times, total_counts, 'b-', label='Total Requests', linewidth=2)
            plt.title('NXDOMAIN vs Total Requests Over Time', fontsize=14, fontweight='bold')
            plt.ylabel('Count')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.xticks(rotation=45)
            
            plt.subplot(2, 1, 2)
            plt.plot(times, rates, 'orange', linewidth=2)
            plt.title('NXDOMAIN Rate Over Time', fontsize=14, fontweight='bold')
            plt.xlabel('Time')
            plt.ylabel('NXDOMAIN Rate (%)')
            plt.grid(True, alpha=0.3)
            plt.xticks(rotation=45)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'nxdomain_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _create_summary_dashboard(self):
        """Create a comprehensive summary dashboard"""
        fig = plt.figure(figsize=(20, 12))
        
        # Create a grid layout
        gs = fig.add_gridspec(3, 4, hspace=0.3, wspace=0.3)
        
        # Key metrics summary (top left)
        ax1 = fig.add_subplot(gs[0, :2])
        metrics_text = f"""
DNS Server Security & Performance Analysis

Total Requests: {self.metrics['total_requests']:,}
Unique Clients: {self.metrics['unique_clients']:,}
NXDOMAIN Rate: {self.metrics['nxdomain_responses']/max(self.metrics['total_requests'],1)*100:.1f}%
Cache Hit Rate: {self.metrics['cache_performance']['hit_rate']:.1f}%

Attack Detection:
• Subdomain Floods: {self.metrics['attack_patterns']['subdomain_flood']:,}
• Amplification Attempts: {self.metrics['attack_patterns']['amplification']:,}
• Suspicious Clients: {len(self.metrics['suspicious_activity']):,}
        """
        ax1.text(0.05, 0.95, metrics_text, transform=ax1.transAxes, fontsize=12,
                verticalalignment='top', fontfamily='monospace',
                bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8))
        ax1.axis('off')
        ax1.set_title('Security Analysis Summary', fontsize=16, fontweight='bold')
        
        # Query type pie chart (top right)
        ax2 = fig.add_subplot(gs[0, 2:])
        if self.metrics['query_types']:
            query_types = dict(self.metrics['query_types'].most_common(6))
            ax2.pie(query_types.values(), labels=query_types.keys(), autopct='%1.1f%%')
            ax2.set_title('Query Type Distribution', fontsize=14, fontweight='bold')
        
        # Requests over time (middle)
        ax3 = fig.add_subplot(gs[1, :])
        if self.metrics['hourly_distribution']:
            times = []
            counts = []
            for time_str, count in sorted(self.metrics['hourly_distribution'].items()):
                times.append(datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S'))
                counts.append(count)
            ax3.plot(times, counts, linewidth=2, color='blue')
            ax3.set_title('DNS Requests Over Time', fontsize=14, fontweight='bold')
            ax3.set_ylabel('Requests per Hour')
            ax3.grid(True, alpha=0.3)
        
        # Top domains (bottom left)
        ax4 = fig.add_subplot(gs[2, :2])
        if self.metrics['queried_domains']:
            top_domains = dict(self.metrics['queried_domains'].most_common(8))
            ax4.barh(range(len(top_domains)), list(top_domains.values()))
            ax4.set_yticks(range(len(top_domains)))
            ax4.set_yticklabels(list(top_domains.keys()))
            ax4.set_title('Top Queried Domains', fontsize=14, fontweight='bold')
            ax4.set_xlabel('Query Count')
        
        # Attack patterns (bottom right)
        ax5 = fig.add_subplot(gs[2, 2:])
        if self.metrics['attack_patterns']:
            attack_data = dict(self.metrics['attack_patterns'])
            bars = ax5.bar(attack_data.keys(), attack_data.values(), 
                          color=['red', 'orange', 'yellow'])
            ax5.set_title('Detected Attack Patterns', fontsize=14, fontweight='bold')
            ax5.set_ylabel('Count')
            for bar in bars:
                height = bar.get_height()
                ax5.text(bar.get_x() + bar.get_width()/2., height,
                        f'{int(height)}', ha='center', va='bottom')
        
        plt.suptitle('DNS Security Analysis Dashboard', fontsize=20, fontweight='bold')
        plt.savefig(self.output_dir / 'security_dashboard.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def save_report(self, report: Dict[str, Any]):
        """Save the analysis report to JSON file"""
        report_file = self.output_dir / 'dns_analysis_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"Report saved to {report_file}")
        
        # Also create a human-readable summary
        summary_file = self.output_dir / 'analysis_summary.txt'
        with open(summary_file, 'w') as f:
            f.write("DNS Security Analysis Report\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("SUMMARY METRICS:\n")
            f.write(f"Total Requests: {report['summary']['total_requests']:,}\n")
            f.write(f"Unique Clients: {report['summary']['unique_clients']:,}\n")
            f.write(f"NXDOMAIN Rate: {report['summary']['nxdomain_rate']}%\n")
            f.write(f"Cache Hit Rate: {report['summary']['cache_hit_rate']}%\n\n")
            
            f.write("SECURITY ANALYSIS:\n")
            f.write(f"Suspicious Clients: {report['attack_analysis']['suspicious_clients']}\n")
            for attack_type, count in report['attack_analysis']['suspected_attacks'].items():
                f.write(f"{attack_type.replace('_', ' ').title()}: {count:,}\n")
            f.write("\n")
            
            f.write("PERFORMANCE METRICS:\n")
            f.write(f"Peak QPS: {report['performance_metrics']['peak_qps']}\n")
            f.write(f"Average QPS: {report['performance_metrics']['avg_qps']}\n")
            f.write(f"Busiest Hour: {report['performance_metrics']['busiest_hour'][0]} ({report['performance_metrics']['busiest_hour'][1]:,} requests)\n")
        
        print(f"Summary saved to {summary_file}")

def main():
    parser = argparse.ArgumentParser(description='DNS Attack Metrics Analyzer')
    parser.add_argument('--log-file', '-l', 
                       default='simulation/server/error.log',
                       help='Path to DNS server log file')
    parser.add_argument('--output-dir', '-o',
                       default='simulation/server/analysis',
                       help='Output directory for reports and visualizations')
    parser.add_argument('--generate-plots', '-p', action='store_true',
                       help='Generate visualization plots')
    
    args = parser.parse_args()
    
    # Check if log file exists
    if not os.path.exists(args.log_file):
        print(f"Error: Log file {args.log_file} not found!")
        sys.exit(1)
    
    print("Starting DNS metrics analysis...")
    analyzer = DNSMetricsAnalyzer(args.log_file, args.output_dir)
    
    # Parse logs and generate metrics
    analyzer.parse_logs()
    
    # Generate report
    report = analyzer.generate_report()
    analyzer.save_report(report)
    
    # Generate visualizations
    if args.generate_plots:
        analyzer.create_visualizations()
    
    print("\nAnalysis complete!")
    print(f"Results saved to: {args.output_dir}")
    
    # Print key findings
    print(f"\nKey Findings:")
    print(f"- Processed {report['summary']['total_requests']:,} DNS requests")
    print(f"- {report['summary']['unique_clients']:,} unique clients")
    print(f"- {report['summary']['nxdomain_rate']}% NXDOMAIN rate")
    print(f"- {report['attack_analysis']['suspicious_clients']} suspicious clients detected")

if __name__ == '__main__':
    main()