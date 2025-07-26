import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class PlottingEngine:
    """Comprehensive plotting and metrics generation for DNS client analysis"""
    
    def __init__(self, metrics, report_dir, file_logger):
        self.metrics = metrics
        self.report_dir = Path(report_dir)
        self.file_logger = file_logger
        
        # Set style for better looking plots
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
        # Create report directory if it doesn't exist
        self.report_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_all_reports(self):
        """Generate all plots and metrics reports"""
        try:
            self.file_logger.info("PLOTTING - Starting comprehensive report generation")
            
            # Generate plots
            self.plot_response_time_distribution()
            self.plot_query_status_pie_chart()
            self.plot_response_time_timeline()
            self.plot_parsing_time_analysis()
            self.plot_metrics_overview()
            self.plot_response_status_bar()
            self.plot_performance_heatmap()
            
            # Generate comprehensive metrics JSON
            self.generate_metrics_json()
            
            # Generate summary dashboard
            self.create_summary_dashboard()
            
            self.file_logger.info(f"PLOTTING - All reports generated successfully in {self.report_dir}")
            
        except Exception as e:
            self.file_logger.error(f"PLOTTING - Error generating reports: {e}")
            raise
    
    def plot_response_time_distribution(self):
        """Plot response time distribution histogram"""
        if not self.metrics.responses_log:
            return
            
        response_times = [r['elapsed'] * 1000 for r in self.metrics.responses_log if r['elapsed'] > 0]
        
        plt.figure(figsize=(12, 6))
        plt.hist(response_times, bins=50, alpha=0.7, color='skyblue', edgecolor='black')
        plt.axvline(np.mean(response_times), color='red', linestyle='--', 
                   label=f'Mean: {np.mean(response_times):.2f}ms')
        plt.axvline(np.median(response_times), color='green', linestyle='--', 
                   label=f'Median: {np.median(response_times):.2f}ms')
        
        plt.xlabel('Response Time (ms)')
        plt.ylabel('Frequency')
        plt.title('DNS Response Time Distribution')
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.report_dir / 'response_time_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_query_status_pie_chart(self):
        """Plot query status distribution as pie chart"""
        labels = ['Success', 'Timeout/Failure', 'Delayed (>1s)']
        sizes = [self.metrics.success, self.metrics.failure, self.metrics.delayed]
        colors = ['#2ecc71', '#e74c3c', '#f39c12']
        
        plt.figure(figsize=(10, 8))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        plt.title('DNS Query Status Distribution')
        plt.axis('equal')
        
        plt.tight_layout()
        plt.savefig(self.report_dir / 'query_status_pie_chart.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_response_time_timeline(self):
        """Plot response time over time"""
        if not self.metrics.responses_log:
            return
            
        response_data = []
        for i, response in enumerate(self.metrics.responses_log):
            response_data.append({
                'query_number': i + 1,
                'response_time': response['elapsed'] * 1000,
                'status': response['status']
            })
        
        df = pd.DataFrame(response_data)
        
        plt.figure(figsize=(15, 8))
        
        # Plot different statuses with different colors
        for status in df['status'].unique():
            subset = df[df['status'] == status]
            plt.scatter(subset['query_number'], subset['response_time'], 
                       label=status, alpha=0.6, s=30)
        
        plt.xlabel('Query Number')
        plt.ylabel('Response Time (ms)')
        plt.title('DNS Response Time Timeline')
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        # Add trend line
        z = np.polyfit(df['query_number'], df['response_time'], 1)
        p = np.poly1d(z)
        plt.plot(df['query_number'], p(df['query_number']), "r--", alpha=0.8, label='Trend')
        
        plt.tight_layout()
        plt.savefig(self.report_dir / 'response_time_timeline.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_parsing_time_analysis(self):
        """Plot parsing time analysis"""
        if not self.metrics.responses_log:
            return
            
        parsing_times = [r['parsing_time'] * 1000000 for r in self.metrics.responses_log]  # Convert to microseconds
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Histogram
        ax1.hist(parsing_times, bins=30, alpha=0.7, color='lightcoral', edgecolor='black')
        ax1.axvline(np.mean(parsing_times), color='red', linestyle='--', 
                   label=f'Mean: {np.mean(parsing_times):.1f}μs')
        ax1.set_xlabel('Parsing Time (μs)')
        ax1.set_ylabel('Frequency')
        ax1.set_title('DNS Response Parsing Time Distribution')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Box plot
        ax2.boxplot(parsing_times, vert=True, patch_artist=True,
                   boxprops=dict(facecolor='lightblue', alpha=0.7))
        ax2.set_ylabel('Parsing Time (μs)')
        ax2.set_title('DNS Response Parsing Time Box Plot')
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.report_dir / 'parsing_time_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_metrics_overview(self):
        """Plot comprehensive metrics overview"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        
        # 1. Success rate over time (sliding window)
        if self.metrics.responses_log:
            window_size = min(10, len(self.metrics.responses_log))
            success_rates = []
            for i in range(window_size, len(self.metrics.responses_log) + 1):
                window = self.metrics.responses_log[i-window_size:i]
                success_count = sum(1 for r in window if r['status'] == 'SUCCESS')
                success_rates.append(success_count / window_size * 100)
            
            ax1.plot(range(window_size, len(self.metrics.responses_log) + 1), success_rates, 'b-', linewidth=2)
            ax1.set_xlabel('Query Number')
            ax1.set_ylabel('Success Rate (%)')
            ax1.set_title(f'Success Rate (Rolling {window_size}-query window)')
            ax1.grid(True, alpha=0.3)
        
        # 2. Response time vs Query type
        if self.metrics.responses_log:
            qtype_data = {}
            for response in self.metrics.responses_log:
                qtype = response['qtype']
                if qtype not in qtype_data:
                    qtype_data[qtype] = []
                qtype_data[qtype].append(response['elapsed'] * 1000)
            
            qtypes = list(qtype_data.keys())
            response_times = [qtype_data[qt] for qt in qtypes]
            
            ax2.boxplot(response_times, labels=qtypes, patch_artist=True)
            ax2.set_xlabel('Query Type')
            ax2.set_ylabel('Response Time (ms)')
            ax2.set_title('Response Time by Query Type')
            ax2.grid(True, alpha=0.3)
        
        # 3. Query volume over time
        query_counts = [i for i in range(1, self.metrics.sent + 1)]
        ax3.plot(query_counts, 'g-', linewidth=2)
        ax3.set_xlabel('Time (Query Sequence)')
        ax3.set_ylabel('Cumulative Queries')
        ax3.set_title('Query Volume Over Time')
        ax3.grid(True, alpha=0.3)
        
        # 4. Performance metrics summary
        metrics_data = {
            'Total Queries': self.metrics.sent,
            'Successful': self.metrics.success,
            'Failed': self.metrics.failure,
            'Delayed': self.metrics.delayed
        }
        
        bars = ax4.bar(metrics_data.keys(), metrics_data.values(), 
                      color=['blue', 'green', 'red', 'orange'], alpha=0.7)
        ax4.set_ylabel('Count')
        ax4.set_title('Query Status Summary')
        ax4.grid(True, alpha=0.3)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig(self.report_dir / 'metrics_overview.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_response_status_bar(self):
        """Plot response status distribution as bar chart"""
        total = self.metrics.sent if self.metrics.sent else 1
        
        categories = ['Successful', 'Failed', 'Delayed']
        values = [self.metrics.success, self.metrics.failure, self.metrics.delayed]
        percentages = [v/total*100 for v in values]
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Count bar chart
        bars1 = ax1.bar(categories, values, color=['#2ecc71', '#e74c3c', '#f39c12'], alpha=0.8)
        ax1.set_ylabel('Count')
        ax1.set_title('DNS Query Status Count')
        ax1.grid(True, alpha=0.3)
        
        for bar, value in zip(bars1, values):
            ax1.text(bar.get_x() + bar.get_width()/2., bar.get_height(),
                    f'{value}', ha='center', va='bottom', fontweight='bold')
        
        # Percentage bar chart
        bars2 = ax2.bar(categories, percentages, color=['#2ecc71', '#e74c3c', '#f39c12'], alpha=0.8)
        ax2.set_ylabel('Percentage (%)')
        ax2.set_title('DNS Query Status Percentage')
        ax2.grid(True, alpha=0.3)
        
        for bar, percentage in zip(bars2, percentages):
            ax2.text(bar.get_x() + bar.get_width()/2., bar.get_height(),
                    f'{percentage:.1f}%', ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(self.report_dir / 'response_status_bar.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_performance_heatmap(self):
        """Plot performance heatmap showing response times by query type and time"""
        if not self.metrics.responses_log:
            return
            
        # Create time buckets (every 10 queries)
        bucket_size = 10
        max_queries = len(self.metrics.responses_log)
        
        # Get unique query types
        qtypes = list(set(r['qtype'] for r in self.metrics.responses_log))
        
        # Create heatmap data
        heatmap_data = []
        for qtype in qtypes:
            qtype_data = []
            for bucket in range(0, max_queries, bucket_size):
                bucket_responses = [r for r in self.metrics.responses_log[bucket:bucket+bucket_size] 
                                  if r['qtype'] == qtype]
                if bucket_responses:
                    avg_time = np.mean([r['elapsed'] * 1000 for r in bucket_responses])
                else:
                    avg_time = 0
                qtype_data.append(avg_time)
            heatmap_data.append(qtype_data)
        
        if heatmap_data and any(any(row) for row in heatmap_data):
            plt.figure(figsize=(12, 8))
            sns.heatmap(heatmap_data, 
                       xticklabels=[f'{i}-{i+bucket_size}' for i in range(0, max_queries, bucket_size)],
                       yticklabels=qtypes,
                       annot=True, fmt='.1f', cmap='YlOrRd')
            plt.xlabel('Query Range')
            plt.ylabel('Query Type')
            plt.title('Response Time Heatmap (ms)')
            
            plt.tight_layout()
            plt.savefig(self.report_dir / 'performance_heatmap.png', dpi=300, bbox_inches='tight')
            plt.close()
    
    def generate_metrics_json(self):
        """Generate comprehensive metrics in JSON format"""
        total = self.metrics.sent if self.metrics.sent else 1
        
        # Calculate statistics
        response_times = [r['elapsed'] * 1000 for r in self.metrics.responses_log if r['elapsed'] > 0]
        parsing_times = [r['parsing_time'] * 1000000 for r in self.metrics.responses_log]
        
        metrics_data = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_queries": self.metrics.sent,
                "successful_queries": self.metrics.success,
                "failed_queries": self.metrics.failure,
                "delayed_queries": self.metrics.delayed,
                "success_rate_percent": round(self.metrics.success * 100 / total, 2),
                "failure_rate_percent": round(self.metrics.failure * 100 / total, 2),
                "delayed_rate_percent": round(self.metrics.delayed * 100 / total, 2)
            },
            "response_time_stats": {
                "mean_ms": round(np.mean(response_times), 3) if response_times else 0,
                "median_ms": round(np.median(response_times), 3) if response_times else 0,
                "std_ms": round(np.std(response_times), 3) if response_times else 0,
                "min_ms": round(min(response_times), 3) if response_times else 0,
                "max_ms": round(max(response_times), 3) if response_times else 0,
                "percentile_95_ms": round(np.percentile(response_times, 95), 3) if response_times else 0,
                "percentile_99_ms": round(np.percentile(response_times, 99), 3) if response_times else 0
            },
            "parsing_time_stats": {
                "mean_microseconds": round(np.mean(parsing_times), 3) if parsing_times else 0,
                "median_microseconds": round(np.median(parsing_times), 3) if parsing_times else 0,
                "std_microseconds": round(np.std(parsing_times), 3) if parsing_times else 0,
                "min_microseconds": round(min(parsing_times), 3) if parsing_times else 0,
                "max_microseconds": round(max(parsing_times), 3) if parsing_times else 0
            },
            "query_type_analysis": self._analyze_by_query_type(),
            "temporal_analysis": self._analyze_temporal_patterns(),
            "raw_data": {
                "requests": self.metrics.requests_log,
                "responses": self.metrics.responses_log
            }
        }
        
        with open(self.report_dir / 'comprehensive_metrics.json', 'w') as f:
            json.dump(metrics_data, f, indent=2)
    
    def _analyze_by_query_type(self):
        """Analyze metrics by query type"""
        qtype_stats = {}
        
        for response in self.metrics.responses_log:
            qtype = response['qtype']
            if qtype not in qtype_stats:
                qtype_stats[qtype] = {
                    'count': 0,
                    'response_times': [],
                    'success_count': 0,
                    'failure_count': 0,
                    'delayed_count': 0
                }
            
            qtype_stats[qtype]['count'] += 1
            qtype_stats[qtype]['response_times'].append(response['elapsed'] * 1000)
            
            if response['status'] == 'SUCCESS':
                qtype_stats[qtype]['success_count'] += 1
            elif response['status'] == 'FAILURE':
                qtype_stats[qtype]['failure_count'] += 1
            elif response['status'] == 'DELAYED':
                qtype_stats[qtype]['delayed_count'] += 1
        
        # Calculate statistics for each query type
        for qtype, stats in qtype_stats.items():
            response_times = stats['response_times']
            total_count = stats['count']
            
            qtype_stats[qtype].update({
                'avg_response_time_ms': round(np.mean(response_times), 3) if response_times else 0,
                'success_rate_percent': round(stats['success_count'] * 100 / total_count, 2),
                'failure_rate_percent': round(stats['failure_count'] * 100 / total_count, 2),
                'delayed_rate_percent': round(stats['delayed_count'] * 100 / total_count, 2)
            })
            
            # Remove raw response_times list for cleaner JSON
            del qtype_stats[qtype]['response_times']
        
        return qtype_stats
    
    def _analyze_temporal_patterns(self):
        """Analyze temporal patterns in the data"""
        if not self.metrics.responses_log:
            return {}
        
        # Analyze patterns in windows of 10 queries
        window_size = 10
        windows = []
        
        for i in range(0, len(self.metrics.responses_log), window_size):
            window = self.metrics.responses_log[i:i+window_size]
            if window:
                success_count = sum(1 for r in window if r['status'] == 'SUCCESS')
                avg_response_time = np.mean([r['elapsed'] * 1000 for r in window])
                
                windows.append({
                    'window_start': i + 1,
                    'window_end': min(i + window_size, len(self.metrics.responses_log)),
                    'success_rate_percent': round(success_count * 100 / len(window), 2),
                    'avg_response_time_ms': round(avg_response_time, 3)
                })
        
        return {
            'window_size': window_size,
            'windows': windows
        }
    
    def create_summary_dashboard(self):
        """Create a comprehensive summary dashboard"""
        fig = plt.figure(figsize=(20, 16))
        
        # Create a 3x3 grid
        gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
        
        # 1. Status pie chart
        ax1 = fig.add_subplot(gs[0, 0])
        labels = ['Success', 'Failure', 'Delayed']
        sizes = [self.metrics.success, self.metrics.failure, self.metrics.delayed]
        colors = ['#2ecc71', '#e74c3c', '#f39c12']
        ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        ax1.set_title('Query Status Distribution')
        
        # 2. Response time histogram
        ax2 = fig.add_subplot(gs[0, 1])
        if self.metrics.responses_log:
            response_times = [r['elapsed'] * 1000 for r in self.metrics.responses_log if r['elapsed'] > 0]
            ax2.hist(response_times, bins=20, alpha=0.7, color='skyblue', edgecolor='black')
            ax2.axvline(np.mean(response_times), color='red', linestyle='--', label=f'Mean: {np.mean(response_times):.2f}ms')
            ax2.set_xlabel('Response Time (ms)')
            ax2.set_ylabel('Frequency')
            ax2.set_title('Response Time Distribution')
            ax2.legend()
        
        # 3. Response time timeline
        ax3 = fig.add_subplot(gs[0, 2])
        if self.metrics.responses_log:
            query_nums = range(1, len(self.metrics.responses_log) + 1)
            response_times = [r['elapsed'] * 1000 for r in self.metrics.responses_log]
            ax3.plot(query_nums, response_times, 'b-', alpha=0.6, linewidth=1)
            ax3.set_xlabel('Query Number')
            ax3.set_ylabel('Response Time (ms)')
            ax3.set_title('Response Time Timeline')
        
        # 4. Metrics bar chart
        ax4 = fig.add_subplot(gs[1, 0])
        categories = ['Total', 'Success', 'Failure', 'Delayed']
        values = [self.metrics.sent, self.metrics.success, self.metrics.failure, self.metrics.delayed]
        bars = ax4.bar(categories, values, color=['blue', 'green', 'red', 'orange'], alpha=0.7)
        ax4.set_ylabel('Count')
        ax4.set_title('Query Metrics Summary')
        for bar, value in zip(bars, values):
            ax4.text(bar.get_x() + bar.get_width()/2., bar.get_height(),
                    f'{value}', ha='center', va='bottom')
        
        # 5. Parsing time analysis
        ax5 = fig.add_subplot(gs[1, 1])
        if self.metrics.responses_log:
            parsing_times = [r['parsing_time'] * 1000000 for r in self.metrics.responses_log]
            ax5.boxplot(parsing_times, patch_artist=True, boxprops=dict(facecolor='lightcoral', alpha=0.7))
            ax5.set_ylabel('Parsing Time (μs)')
            ax5.set_title('Parsing Time Distribution')
        
        # 6. Success rate over time
        ax6 = fig.add_subplot(gs[1, 2])
        if self.metrics.responses_log:
            window_size = min(5, len(self.metrics.responses_log))
            success_rates = []
            for i in range(window_size, len(self.metrics.responses_log) + 1):
                window = self.metrics.responses_log[i-window_size:i]
                success_count = sum(1 for r in window if r['status'] == 'SUCCESS')
                success_rates.append(success_count / window_size * 100)
            
            ax6.plot(range(window_size, len(self.metrics.responses_log) + 1), success_rates, 'g-', linewidth=2)
            ax6.set_xlabel('Query Number')
            ax6.set_ylabel('Success Rate (%)')
            ax6.set_title(f'Rolling Success Rate ({window_size}-query window)')
        
        # 7-9. Statistics text panels
        ax7 = fig.add_subplot(gs[2, :])
        ax7.axis('off')
        
        # Calculate comprehensive statistics
        total = self.metrics.sent if self.metrics.sent else 1
        if self.metrics.responses_log:
            response_times = [r['elapsed'] * 1000 for r in self.metrics.responses_log if r['elapsed'] > 0]
            parsing_times = [r['parsing_time'] * 1000000 for r in self.metrics.responses_log]
            
            stats_text = f"""
COMPREHENSIVE DNS CLIENT ANALYSIS REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

QUERY STATISTICS:
• Total Queries Sent: {self.metrics.sent}
• Successful Responses: {self.metrics.success} ({self.metrics.success*100/total:.2f}%)
• Failed Responses: {self.metrics.failure} ({self.metrics.failure*100/total:.2f}%)
• Delayed Responses (>1s): {self.metrics.delayed} ({self.metrics.delayed*100/total:.2f}%)

RESPONSE TIME ANALYSIS:
• Mean Response Time: {np.mean(response_times):.3f} ms
• Median Response Time: {np.median(response_times):.3f} ms
• 95th Percentile: {np.percentile(response_times, 95):.3f} ms
• 99th Percentile: {np.percentile(response_times, 99):.3f} ms
• Min/Max Response Time: {min(response_times):.3f} / {max(response_times):.3f} ms

PARSING PERFORMANCE:
• Mean Parsing Time: {np.mean(parsing_times):.1f} μs
• Median Parsing Time: {np.median(parsing_times):.1f} μs
• Total Parsing Time: {sum(parsing_times):.1f} μs
"""
        else:
            stats_text = "No response data available for analysis."
        
        ax7.text(0.05, 0.95, stats_text, transform=ax7.transAxes, fontsize=11,
                verticalalignment='top', fontfamily='monospace',
                bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.8))
        
        plt.suptitle('DNS Client Performance Dashboard', fontsize=16, fontweight='bold')
        plt.savefig(self.report_dir / 'comprehensive_dashboard.png', dpi=300, bbox_inches='tight')
        plt.close()