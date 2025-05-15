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
    """Main test function."""
    print("\n=== LVC-SSI Framework Test ===")
    print(f"Started at: {datetime.utcnow().isoformat()}\n")
    
    # Initialize managers
    did_manager = DIDManager()
    vc_manager = VCManager()
    zkp_prover = ZKPProver()
    perf_monitor = PerformanceMonitor()
    
    try:
        # 1. Create DIDs
        print("1. Creating DIDs...")
        async with perf_monitor.measure("did_creation"):
            # Create operator DID
            operator_did = await did_manager.create_did("Simulation Operator")
            print(f"Operator DID: {operator_did}")
            operator_doc = await did_manager.resolve_did(operator_did)
            print(f"Operator DID Document: {json.dumps(operator_doc, indent=2)}")
            
            # Create commander DID
            commander_did = await did_manager.create_did("Commander")
            print(f"Commander DID: {commander_did}")
            commander_doc = await did_manager.resolve_did(commander_did)
            print(f"Commander DID Document: {json.dumps(commander_doc, indent=2)}")
        
        # 2. Issue credential
        print("\n2. Issuing credential...")
        async with perf_monitor.measure("credential_issuance"):
            # Get commander's private key for signing
            commander_key = commander_doc["verificationMethod"][0]["privateKeyPem"]
            
            # Issue credential to operator
            credential = await vc_manager.issue_credential(
                subject_did=operator_did,
                issuer_did=commander_did,
                credential_type="SimulationAccess",
                attributes={
                    "role": "simulation_operator",
                    "clearance": "top_secret",
                    "simulations": ["tactical", "strategic"]
                },
                private_key_pem=commander_key
            )
            print(f"Issued Credential: {json.dumps(credential, indent=2)}")
        
        # 3. Generate ZKP
        print("\n3. Generating ZKP...")
        async with perf_monitor.measure("zkp_generation"):
            # Compile circuits
            await zkp_prover.compile_circuits()
            
            # Setup prover
            await zkp_prover.setup()
            
            # Generate witness
            witness = await zkp_prover.generate_witness(
                credential=credential,
                revealed_attributes=["role", "clearance"]
            )
            
            # Generate proof
            proof = await zkp_prover.generate_proof(witness)
            print(f"Generated ZKP: {json.dumps(proof, indent=2)}")
        
        # 4. Verify ZKP
        print("\n4. Verifying ZKP...")
        async with perf_monitor.measure("zkp_verification"):
            verifier = ZKPVerifier()
            is_valid = await verifier.verify_proof(proof)
            print(f"Proof valid: {is_valid}")
        
        # Print performance metrics
        perf_monitor.print_metrics()
        
    except Exception as e:
        print(f"\nError during test execution: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    asyncio.run(main()) 