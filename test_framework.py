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
from datetime import datetime

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
        operator_did = await did_manager.create_did("Simulation Operator")
        commander_did = await did_manager.create_did("Commander")
    
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
            }
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