from src.did.did_manager import DIDManager
from src.vc.vc_manager import VCManager
from src.zkp.zkp_prover import ZKPProver
from src.sig.simulation_gateway import SimulationGateway, AccessRequest
from src.utils.performance_monitor import PerformanceMonitor
import json
import os
import platform
import subprocess
import asyncio
import time

def setup_zokrates():
    """Setup ZoKrates based on the platform."""
    system = platform.system()
    
    if system == "Windows":
        # Check if ZoKrates is in PATH
        try:
            subprocess.run(['zokrates', '--version'], capture_output=True, check=True)
            print("ZoKrates is already installed and in PATH")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("Please install ZoKrates for Windows:")
            print("1. Download from: https://github.com/Zokrates/ZoKrates/releases")
            print("2. Extract the zip file")
            print("3. Add the extracted directory to your system PATH")
            print("4. Restart your terminal")
            return False
    else:
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
    
    if system == "Windows":
        commands = [
            ['zokrates', 'compile', '-i', 'access_control.zok'],
            ['zokrates', 'setup'],
            ['zokrates', 'export-verifier']
        ]
    else:
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
    perf_monitor = PerformanceMonitor()

    print("\n=== Testing LVC-SSI Framework ===\n")
    total_start_time = time.time()

    # 1. Create a DID for a simulation operator
    print("1. Creating DID for simulation operator...")
    perf_monitor.start_operation("did_creation")
    operator_did, operator_doc = did_manager.create_did("simulation_operator")
    perf_monitor.end_operation("did_creation")
    print(f"Created DID: {operator_did}")
    print(f"DID Document: {json.dumps(operator_doc, indent=2)}\n")

    # 2. Create a DID for the issuer (e.g., a commander)
    print("2. Creating DID for commander (issuer)...")
    perf_monitor.start_operation("did_creation")
    commander_did, commander_doc = did_manager.create_did("commander")
    perf_monitor.end_operation("did_creation")
    print(f"Created DID: {commander_did}\n")

    # 3. Issue a credential to the operator
    print("3. Issuing credential to operator...")
    perf_monitor.start_operation("credential_issuance")
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
    perf_monitor.end_operation("credential_issuance")
    print(f"Issued Credential: {json.dumps(credential, indent=2)}\n")

    # 4. Generate a ZKP for access control
    print("4. Generating ZKP for access control...")
    try:
        if setup_zokrates():
            if compile_circuit():
                private_inputs = {
                    "role": "operator",
                    "clearance_level": "high"
                }
                
                # Monitor ZKP operations
                perf_monitor.start_operation("zkp_compilation")
                # Compile circuit
                perf_monitor.end_operation("zkp_compilation")
                
                perf_monitor.start_operation("zkp_setup")
                # Setup circuit
                perf_monitor.end_operation("zkp_setup")
                
                perf_monitor.start_operation("zkp_witness")
                # Compute witness
                perf_monitor.end_operation("zkp_witness")
                
                perf_monitor.start_operation("zkp_proof")
                proof = zkp_prover.generate_proof(
                    credential=credential,
                    proof_type="access_control",
                    private_inputs=private_inputs
                )
                perf_monitor.end_operation("zkp_proof")
                
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
    gateway.add_access_policy(
        resource_id="tactical_simulation",
        policy={
            "public_inputs": {
                "required_role": "operator",
                "required_clearance": "high"
            }
        }
    )

    perf_monitor.start_operation("access_control")
    if proof is not None:
        print(f"Using proof ID: {proof['proof_id']}")
        print(f"Proof cache contents: {list(zkp_prover.proof_cache.keys())}")
        access_response = await gateway.handle_access_request(AccessRequest(
            proof_id=proof["proof_id"],
            resource_id="tactical_simulation",
            action="execute"
        ))
    else:
        print("Falling back to credential-based access control")
        access_response = await gateway.handle_access_request(AccessRequest(
            credential=credential,
            resource_id="tactical_simulation",
            action="execute"
        ))
    perf_monitor.end_operation("access_control")
    print(f"Access Response: {json.dumps(access_response.model_dump(), indent=2)}\n")

    # 6. Access Logs
    print("6. Access Logs:")
    logs = await gateway.get_access_logs()
    print(json.dumps(logs, indent=2))

    # Calculate total execution time
    total_execution_time = (time.time() - total_start_time) * 1000  # Convert to milliseconds

    # Print performance metrics
    print("\n=== Performance Summary ===")
    print(f"Total Execution Time: {total_execution_time:.2f}ms")
    perf_monitor.print_metrics()
    
    # Save metrics
    perf_monitor.save_metrics()

if __name__ == "__main__":
    asyncio.run(main()) 