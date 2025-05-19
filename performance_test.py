import time
import asyncio
import statistics
from src.did.did_manager import DIDManager
from src.vc.vc_manager import VCManager
from src.zkp.zkp_prover import ZKPProver
from src.sig.simulation_gateway import SimulationGateway, AccessRequest
import json
import os

class PerformanceMetrics:
    def __init__(self):
        self.metrics = {}
        
    def add_metric(self, operation: str, duration: float):
        if operation not in self.metrics:
            self.metrics[operation] = []
        self.metrics[operation].append(duration)
        
    def get_statistics(self):
        stats = {}
        for operation, durations in self.metrics.items():
            stats[operation] = {
                'count': len(durations),
                'min': min(durations),
                'max': max(durations),
                'mean': statistics.mean(durations),
                'median': statistics.median(durations),
                'std_dev': statistics.stdev(durations) if len(durations) > 1 else 0
            }
        return stats

async def run_performance_test(iterations: int = 10):
    metrics = PerformanceMetrics()
    
    print(f"\n=== Running Performance Tests ({iterations} iterations) ===\n")
    
    # Initialize components
    did_manager = DIDManager()
    vc_manager = VCManager()
    zkp_prover = ZKPProver()
    gateway = SimulationGateway(zkp_prover=zkp_prover)
    
    for i in range(iterations):
        print(f"\nIteration {i + 1}/{iterations}")
        
        # 1. DID Creation Performance
        start_time = time.time()
        operator_did, operator_doc = did_manager.create_did("simulation_operator")
        commander_did, commander_doc = did_manager.create_did("commander")
        duration = time.time() - start_time
        metrics.add_metric('did_creation', duration)
        print(f"DID Creation: {duration:.4f} seconds")
        
        # 2. Credential Issuance Performance
        start_time = time.time()
        credential = vc_manager.issue_credential(
            subject_did=operator_did,
            issuer_did=commander_did,
            credential_type="simulation_access",
            attributes={
                "role": "operator",
                "clearance_level": "high",
                "allowed_simulations": ["tactical", "strategic"]
            },
            private_key_pem=commander_doc["verificationMethod"][0]["privateKeyPem"],
            validity_days=30
        )
        duration = time.time() - start_time
        metrics.add_metric('credential_issuance', duration)
        print(f"Credential Issuance: {duration:.4f} seconds")
        
        # 3. ZKP Generation Performance
        start_time = time.time()
        try:
            private_inputs = {
                "role": "operator",
                "clearance_level": "high"
            }
            proof = zkp_prover.generate_proof(
                credential=credential,
                proof_type="access_control",
                private_inputs=private_inputs
            )
            duration = time.time() - start_time
            metrics.add_metric('zkp_generation', duration)
            print(f"ZKP Generation: {duration:.4f} seconds")
        except Exception as e:
            print(f"ZKP Generation failed: {str(e)}")
            metrics.add_metric('zkp_generation', 0)
        
        # 4. Access Control Performance
        gateway.add_access_policy(
            resource_id="tactical_simulation",
            policy={
                "public_inputs": {
                    "required_role": "operator",
                    "required_clearance": "high"
                }
            }
        )
        
        start_time = time.time()
        if 'proof' in locals():
            access_response = await gateway.handle_access_request(AccessRequest(
                proof_id=proof["proof_id"],
                resource_id="tactical_simulation",
                action="execute"
            ))
        else:
            access_response = await gateway.handle_access_request(AccessRequest(
                credential=credential,
                resource_id="tactical_simulation",
                action="execute"
            ))
        duration = time.time() - start_time
        metrics.add_metric('access_control', duration)
        print(f"Access Control: {duration:.4f} seconds")
        
        # 5. DID Resolution Performance
        start_time = time.time()
        resolved_doc = did_manager.resolve_did(operator_did)
        duration = time.time() - start_time
        metrics.add_metric('did_resolution', duration)
        print(f"DID Resolution: {duration:.4f} seconds")
        
        # 6. Access Logs Performance
        start_time = time.time()
        logs = await gateway.get_access_logs()
        duration = time.time() - start_time
        metrics.add_metric('access_logs', duration)
        print(f"Access Logs: {duration:.4f} seconds")
    
    # Print final statistics
    print("\n=== Performance Statistics ===")
    stats = metrics.get_statistics()
    for operation, stat in stats.items():
        print(f"\n{operation}:")
        print(f"  Count: {stat['count']}")
        print(f"  Min: {stat['min']:.4f} seconds")
        print(f"  Max: {stat['max']:.4f} seconds")
        print(f"  Mean: {stat['mean']:.4f} seconds")
        print(f"  Median: {stat['median']:.4f} seconds")
        print(f"  Std Dev: {stat['std_dev']:.4f} seconds")

if __name__ == "__main__":
    asyncio.run(run_performance_test()) 