import asyncio
import json
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from src.did.did_manager import DIDManager
from src.vc.vc_manager import VCManager
from src.zkp.zkp_prover import ZKPProver
from src.sig.simulation_gateway import SimulationGateway
from src.utils.performance_monitor import PerformanceMonitor

class TestFramework:
    """Test framework for LVC-SSI Framework with optimized performance."""
    
    def __init__(self):
        """Initialize the test framework with managers and executor."""
        self.did_manager = DIDManager()
        self.vc_manager = VCManager()
        self.zkp_prover = ZKPProver()
        self.perf_monitor = PerformanceMonitor()
        self.executor = ThreadPoolExecutor(max_workers=4)
    
    async def create_dids(self):
        """Create DIDs for operator and commander in parallel."""
        print("1. Creating DIDs...")
        async with self.perf_monitor.measure("did_creation"):
            # Create DIDs concurrently
            operator_task = self.did_manager.create_did("Simulation Operator")
            commander_task = self.did_manager.create_did("Commander")
            
            operator_did, operator_doc = await operator_task
            commander_did, commander_doc = await commander_task
            
            print(f"Operator DID: {operator_did}")
            print(f"Operator DID Document: {json.dumps(operator_doc, indent=2)}")
            print(f"Commander DID: {commander_did}")
            print(f"Commander DID Document: {json.dumps(commander_doc, indent=2)}")
            
            return operator_did, operator_doc, commander_did, commander_doc
    
    async def issue_credential(self, operator_did, commander_did, commander_doc):
        """Issue a credential to the operator."""
        print("\n2. Issuing credential...")
        async with self.perf_monitor.measure("credential_issuance"):
            commander_key = commander_doc["verificationMethod"][0]["privateKeyPem"]
            
            credential = await self.vc_manager.issue_credential(
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
            return credential
    
    async def generate_zkp(self, credential):
        """Generate a zero-knowledge proof for the credential."""
        print("\n3. Generating ZKP...")
        async with self.perf_monitor.measure("zkp_generation"):
            proof = await self.zkp_prover.generate_proof(
                credential=credential,
                proof_type="access_control",
                private_inputs={
                    "role": "simulation_operator",
                    "clearance_level": "top_secret"
                }
            )
            print(f"Generated ZKP: {json.dumps(proof, indent=2)}")
            return proof
    
    async def verify_zkp(self, proof, credential):
        """Verify the zero-knowledge proof."""
        print("\n4. Verifying ZKP...")
        async with self.perf_monitor.measure("zkp_verification"):
            is_valid = await self.zkp_prover.verify_proof(
                proof=proof,
                public_inputs={
                    "credential_id": credential["id"],
                    "issuer": credential["issuer"],
                    "expiration_date": credential["expirationDate"],
                    "credential_type": credential["type"][1]
                }
            )
            print(f"Proof valid: {is_valid}")
            return is_valid
    
    async def run_test(self):
        """Run the complete test suite."""
        print("\n=== LVC-SSI Framework Test ===")
        print(f"Started at: {datetime.now(timezone.utc).isoformat()}\n")
        
        try:
            # Create DIDs
            operator_did, operator_doc, commander_did, commander_doc = await self.create_dids()
            
            # Issue credential
            credential = await self.issue_credential(operator_did, commander_did, commander_doc)
            
            # Generate and verify ZKP
            proof = await self.generate_zkp(credential)
            is_valid = await self.verify_zkp(proof, credential)
            
            # Print performance metrics
            self.perf_monitor.print_metrics()
            
            return is_valid
            
        except Exception as e:
            print(f"\nError during test execution: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            self.executor.shutdown()

async def main():
    """Main entry point for the test framework."""
    framework = TestFramework()
    return await framework.run_test()

if __name__ == "__main__":
    asyncio.run(main()) 