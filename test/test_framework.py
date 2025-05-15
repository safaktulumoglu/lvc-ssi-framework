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
    print("\n=== LVC-SSI Framework Test ===")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Initialize performance monitor and managers
    perf_monitor = PerformanceMonitor()
    did_manager = DIDManager()
    vc_manager = VCManager()
    zkp_prover = ZKPProver()
    gateway = SimulationGateway()
    
    try:
        # 1. Create DIDs
        print("1. Creating DIDs...")
        async with perf_monitor.measure("did_creation"):
            operator_did, operator_doc = await did_manager.create_did("Simulation Operator")
            print(f"Operator DID: {operator_did}")
            print(f"Operator DID Document: {json.dumps(operator_doc, indent=2)}")
            
            commander_did, commander_doc = await did_manager.create_did("Commander")
            print(f"Commander DID: {commander_did}")
            print(f"Commander DID Document: {json.dumps(commander_doc, indent=2)}")
        
        # 2. Issue credential
        print("\n2. Issuing credential...")
        async with perf_monitor.measure("credential_issuance"):
            # Get the private key from the commander's DID document
            private_key_pem = commander_doc["verificationMethod"][0]["privateKeyPem"]
            
            credential = await vc_manager.issue_credential(
                operator_did,  # subject_did
                commander_did,  # issuer_did
                "SimulationAccess",  # credential_type
                {  # attributes
                    "role": "simulation_operator",
                    "clearance": "top_secret",
                    "simulations": ["tactical", "strategic"]
                },
                private_key_pem  # private_key_pem as positional argument
            )
            print(f"Issued Credential: {json.dumps(credential, indent=2)}")
        
        # 3. Generate ZKP
        print("\n3. Generating ZKP...")
        async with perf_monitor.measure("zkp_compilation"):
            circuit = await zkp_prover.compile_circuit("access_control")
            print(f"Compiled Circuit: {circuit}")
        
        async with perf_monitor.measure("zkp_setup"):
            setup = await zkp_prover.setup_circuit(circuit)
            print(f"Circuit Setup: {setup}")
        
        async with perf_monitor.measure("zkp_witness"):
            witness = await zkp_prover.generate_witness(circuit, {
                "credential": credential,
                "statement": "has_access"
            })
            print(f"Generated Witness: {witness}")
        
        async with perf_monitor.measure("zkp_proof"):
            proof = await zkp_prover.generate_proof(circuit, setup, witness)
            print(f"Generated Proof: {proof}")
        
        # 4. Test access control
        print("\n4. Testing access control...")
        async with perf_monitor.measure("access_control"):
            access_request = {
                "requester_did": operator_did,
                "proof": proof,
                "credential_id": credential["id"]
            }
            
            response = await gateway.handle_access_request(access_request)
            print(f"Access Control Response: {json.dumps(response, indent=2)}")
        
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
        
        print(f"\nTotal Execution Time: {perf_monitor.get_total_time():.2f}ms")
        
    except Exception as e:
        print(f"\nError during test execution: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main()) 