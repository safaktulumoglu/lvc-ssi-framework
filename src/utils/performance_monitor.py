import time
from typing import Dict, Any
from contextlib import asynccontextmanager
import json
import os
from datetime import datetime

class PerformanceMonitor:
    def __init__(self):
        self.metrics: Dict[str, Dict[str, Any]] = {}
        self.start_time = time.time()
        self.log_file = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'performance_logs.json')
        
    @asynccontextmanager
    async def measure(self, operation: str):
        """Measure the execution time of an operation."""
        start = time.time()
        try:
            yield
        finally:
            end = time.time()
            duration = (end - start) * 1000  # Convert to milliseconds
            
            if operation not in self.metrics:
                self.metrics[operation] = {
                    "count": 0,
                    "min": float('inf'),
                    "max": float('-inf'),
                    "total": 0,
                    "avg": 0
                }
            
            metrics = self.metrics[operation]
            metrics["count"] += 1
            metrics["min"] = min(metrics["min"], duration)
            metrics["max"] = max(metrics["max"], duration)
            metrics["total"] += duration
            metrics["avg"] = metrics["total"] / metrics["count"]
    
    def get_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get all performance metrics."""
        return self.metrics
    
    def get_total_time(self) -> float:
        """Get total execution time in milliseconds."""
        return (time.time() - self.start_time) * 1000
    
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
        for operation, metrics in self.metrics.items():
            total += metrics["total"]
        return total 