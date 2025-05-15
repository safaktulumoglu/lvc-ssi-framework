import asyncio
import json
import time
from datetime import datetime
from src.did.did_manager import DIDManager
from src.vc.vc_manager import VCManager
from src.zkp.zkp_prover import ZKPProver
from src.sig.simulation_gateway import SimulationGateway
from src.utils.performance_monitor import PerformanceMonitor

async def main():
    # Initialize performance monitor and managers
    perf_monitor = PerformanceMonitor()
    did_manager = DIDManager()
    vc_manager = VCManager()
    zkp_prover = ZKPProver()
    gateway = SimulationGateway()
    
    print("\n=== LVC-SSI Framework Test ===")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Create DIDs for simulation operator and commander
    print("\n1. Creating DIDs...")
    with perf_monitor.measure("did_creation"):
        operator_did, operator_doc = await did_manager.create_did("Simulation Operator")
        commander_did, commander_doc = await did_manager.create_did("Commander")
    
    print(f"Operator DID: {operator_did}")
    print(f"Commander DID: {commander_did}")
    
    # Issue credential to operator
    print("\n2. Issuing credential...")
    with perf_monitor.measure("credential_issuance"):
        credential = await vc_manager.issue_credential(
            subject_did=operator_did,
            issuer_did=commander_did,
            credential_type="SimulationAccess",
            attributes={
                "role": "operator",
                "clearance": "top_secret",
                "simulations": ["tactical", "strategic"]
            },
            private_key_pem=commander_doc["verificationMethod"][0]["privateKeyPem"]
        )
    
    print(f"Issued credential: {json.dumps(credential, indent=2)}")
    
    # Generate ZKP for access control
    print("\n3. Generating ZKP...")
    with perf_monitor.measure("zkp_generation"):
        proof = await zkp_prover.generate_proof(
            credential=credential,
            statement="has_clearance('top_secret')"
        )
    
    print(f"Generated proof: {json.dumps(proof, indent=2)}")
    
    # Test access control
    print("\n4. Testing access control...")
    with perf_monitor.measure("access_control"):
        access_request = {
            "proof_id": proof["id"],
            "credential_id": credential["id"],
            "resource_id": "simulation_engine",
            "action": "start_simulation"
        }
        
        response = await gateway.handle_access_request(access_request)
    
    print(f"Access control response: {json.dumps(response, indent=2)}")
    
    # Print performance summary
    print("\n=== Performance Summary ===")
    metrics = perf_monitor.get_metrics()
    for operation, stats in metrics.items():
        print(f"\n{operation}:")
        print(f"  Count: {stats['count']}")
        print(f"  Min: {stats['min']:.2f}ms")
        print(f"  Max: {stats['max']:.2f}ms")
        print(f"  Avg: {stats['avg']:.2f}ms")
        print(f"  Total: {stats['total']:.2f}ms")
    
    print(f"\nTotal execution time: {perf_monitor.get_total_time():.2f}ms")
    print(f"\nCompleted at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    asyncio.run(main()) 