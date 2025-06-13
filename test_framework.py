from src.did.did_manager import DIDManager
from src.vc.vc_manager import VCManager
from src.zkp.zkp_prover import ZKPProver
from src.sig.simulation_gateway import SimulationGateway, AccessRequest
import json
import os
import platform
import subprocess
import asyncio

def setup_zokrates():
    """Setup ZoKrates based on the platform."""
    system = platform.system()
    
    # For Linux/MacOS, use Docker
    try:
        subprocess.run(['docker', 'pull', 'zokrates/zokrates'], check=True)
        print("ZoKrates Docker image pulled successfully")
    except subprocess.CalledProcessError:
        print("Failed to pull ZoKrates Docker image")
        return False
    
    return True

def compile_circuit():
    """Compile the ZoKrates circuit."""
    system = platform.system()
    circuit_dir = os.path.join('src', 'circuits')
    abs_circuit_dir = os.path.abspath(circuit_dir)
    
    # Use Docker for Linux/MacOS
    # Note: Using /home/zokrates/.zokrates/bin/zokrates for the executable path
    commands = [
        ['docker', 'run', '-v', f'{abs_circuit_dir}:/home/zokrates/code', 
         '-w', '/home/zokrates/code', 'zokrates/zokrates', '/home/zokrates/.zokrates/bin/zokrates', 'compile', '-i', 'access_control.zok'],
        ['docker', 'run', '-v', f'{abs_circuit_dir}:/home/zokrates/code', 
         '-w', '/home/zokrates/code', 'zokrates/zokrates', '/home/zokrates/.zokrates/bin/zokrates', 'setup'],
        ['docker', 'run', '-v', f'{abs_circuit_dir}:/home/zokrates/code', 
         '-w', '/home/zokrates/code', 'zokrates/zokrates', '/home/zokrates/.zokrates/bin/zokrates', 'export-verifier']
    ]
    
    try:
        for cmd in commands:
            print(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            print(f"Command output: {result.stdout}")
            if result.stderr:
                print(f"Command stderr: {result.stderr}")
        print("Circuit compiled successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error compiling circuit: {str(e)}")
        if e.stdout:
            print(f"Command stdout: {e.stdout}")
        if e.stderr:
            print(f"Command stderr: {e.stderr}")
        return False

async def main():
    # Initialize components
    did_manager = DIDManager()
    vc_manager = VCManager()
    zkp_prover = ZKPProver()
    gateway = SimulationGateway(zkp_prover=zkp_prover)

    print("\n=== Testing LVC-SSI Framework ===\n")

    # 1. Create a DID for a simulation operator
    print("1. Creating DID for simulation operator...")
    operator_did, operator_doc = did_manager.create_did("simulation_operator")
    print(f"Created DID: {operator_did}")
    print(f"DID Document: {json.dumps(operator_doc, indent=2)}\n")

    # 2. Create a DID for the issuer (e.g., a commander)
    print("2. Creating DID for commander (issuer)...")
    commander_did, commander_doc = did_manager.create_did("commander")
    print(f"Created DID: {commander_did}\n")

    # 3. Issue a credential to the operator
    print("3. Issuing credential to operator...")
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
    print(f"Issued Credential: {json.dumps(credential, indent=2)}\n")

    # 4. Generate a ZKP for access control (optional)
    print("4. Generating ZKP for access control...")
    try:
        # Setup ZoKrates
        if setup_zokrates():
            # Compile the circuit
            if compile_circuit():
                private_inputs = {
                    "role": "operator",
                    "clearance_level": "high"
                }
                proof = zkp_prover.generate_proof(
                    credential=credential,
                    proof_type="access_control",
                    private_inputs=private_inputs
                )
                print(f"Generated Proof: {json.dumps(proof, indent=2)}\n")
            else:
                print("Skipping ZKP generation due to circuit compilation failure")
                proof = None
        else:
            print("Skipping ZKP generation due to ZoKrates not being installed")
            proof = None
    except Exception as e:
        print(f"Error during ZKP generation: {str(e)}")
        print("Continuing with access control test without ZKP...")
        proof = None

    # 5. Test access control
    print("5. Testing access control...")
    # Add an access policy
    gateway.add_access_policy(
        resource_id="tactical_simulation",
        policy={
            "public_inputs": {
                "required_role": "operator",
                "required_clearance": "high"
            }
        }
    )

    # Test access request
    if proof is not None:
        print(f"Using proof ID: {proof['proof_id']}")
        print(f"Proof cache contents: {list(zkp_prover.proof_cache.keys())}")
        access_response = await gateway.handle_access_request(AccessRequest(
            proof_id=proof["proof_id"],
            resource_id="tactical_simulation",
            action="execute"
        ))
    else:
        # Fallback to credential-based access control without ZKP
        print("Falling back to credential-based access control")
        access_response = await gateway.handle_access_request(AccessRequest(
            credential=credential,
            resource_id="tactical_simulation",
            action="execute"
        ))
    print(f"Access Response: {json.dumps(access_response.model_dump(), indent=2)}\n")

    # 6. Access Logs
    print("6. Access Logs:")
    logs = await gateway.get_access_logs()
    print(json.dumps(logs, indent=2))

if __name__ == "__main__":
    asyncio.run(main()) 
