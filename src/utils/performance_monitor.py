import time
from typing import Dict, List
from datetime import datetime
import json
import os

class PerformanceMonitor:
    def __init__(self):
        self.metrics: Dict[str, List[float]] = {
            "did_creation": [],
            "credential_issuance": [],
            "zkp_compilation": [],
            "zkp_setup": [],
            "zkp_witness": [],
            "zkp_proof": [],
            "access_control": []
        }
        self.start_times: Dict[str, float] = {}
        self.log_file = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'performance_logs.json')
        
    def start_operation(self, operation: str):
        """Start timing an operation."""
        self.start_times[operation] = time.time()
        
    def end_operation(self, operation: str):
        """End timing an operation and record the duration in milliseconds."""
        if operation in self.start_times:
            duration = (time.time() - self.start_times[operation]) * 1000  # Convert to milliseconds
            self.metrics[operation].append(duration)
            del self.start_times[operation]
            
    def get_metrics(self) -> Dict[str, Dict[str, float]]:
        """Get performance metrics with statistics in milliseconds."""
        stats = {}
        for operation, durations in self.metrics.items():
            if durations:
                stats[operation] = {
                    "min": min(durations),
                    "max": max(durations),
                    "avg": sum(durations) / len(durations),
                    "count": len(durations),
                    "total": sum(durations)
                }
        return stats
    
    def save_metrics(self):
        """Save metrics to file."""
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        with open(self.log_file, 'w') as f:
            json.dump({
                "timestamp": datetime.utcnow().isoformat(),
                "metrics": self.get_metrics()
            }, f, indent=2)
            
    def print_metrics(self):
        """Print current performance metrics in milliseconds."""
        print("\n=== Performance Metrics (milliseconds) ===")
        stats = self.get_metrics()
        for operation, metrics in stats.items():
            print(f"\n{operation}:")
            print(f"  Count: {metrics['count']}")
            print(f"  Min: {metrics['min']:.2f}ms")
            print(f"  Max: {metrics['max']:.2f}ms")
            print(f"  Avg: {metrics['avg']:.2f}ms")
            print(f"  Total: {metrics['total']:.2f}ms")
            
    def get_total_execution_time(self) -> float:
        """Get total execution time in milliseconds."""
        total = 0
        for operation, durations in self.metrics.items():
            total += sum(durations)
        return total 