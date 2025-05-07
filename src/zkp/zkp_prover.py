from typing import Dict, Any
import json
import subprocess
import os
import platform
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64

class ZKPProver:
    def __init__(self):
        self.proof_cache: Dict[str, Any] = {}
        self.working_dir = os.path.join(os.path.dirname(__file__), '..', 'circuits')
        self.abs_working_dir = os.path.abspath(self.working_dir)
        
    def _run_zokrates_command(self, command: list) -> subprocess.CompletedProcess:
        """Run a ZoKrates command using Docker."""
        docker_cmd = [
            'docker', 'run', '-v', f'{self.abs_working_dir}:/home/zokrates/code',
            '-w', '/home/zokrates/code', 'zokrates/zokrates',
            '/home/zokrates/.zokrates/bin/zokrates'
        ] + command
        return subprocess.run(docker_cmd, check=True, capture_output=True, text=True)
        
    def generate_proof(self, 
                      credential: dict,
                      proof_type: str,
                      private_inputs: dict) -> dict:
        """
        Generate a Zero-Knowledge Proof for a credential.
        
        Args:
            credential: The Verifiable Credential to prove
            proof_type: Type of proof to generate (e.g., 'access_control')
            private_inputs: Private inputs for the proof
            
        Returns:
            dict: The generated proof
        """
        try:
            # Convert credential to proof inputs
            public_inputs = self._prepare_public_inputs(credential)
            
            # Prepare input files
            circuit_path = f"{proof_type}.zok"
            witness_path = f"{proof_type}.wtns"
            proof_path = f"{proof_type}.proof.json"
            
            # Compile the circuit
            self._run_zokrates_command(['compile', '-i', circuit_path])
            
            # Setup the circuit
            self._run_zokrates_command(['setup'])
            
            # Compute witness
            witness_input = json.dumps([*public_inputs.values(), *private_inputs.values()])
            self._run_zokrates_command(['compute-witness', '-a', *witness_input.split()])
            
            # Generate proof
            self._run_zokrates_command(['generate-proof'])
            
            # Read the proof
            with open(os.path.join(self.working_dir, proof_path), 'r') as f:
                proof = json.load(f)
            
            # Cache the proof
            proof_id = self._generate_proof_id(credential["id"], proof_type)
            self.proof_cache[proof_id] = proof
            
            return {
                "proof_id": proof_id,
                "proof_type": proof_type,
                "credential_id": credential["id"],
                "proof": proof
            }
        except subprocess.CalledProcessError as e:
            print(f"Error generating proof: {str(e)}")
            if e.stdout:
                print(f"Command stdout: {e.stdout}")
            if e.stderr:
                print(f"Command stderr: {e.stderr}")
            return None
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            return None
    
    def verify_proof(self, 
                    proof: dict,
                    public_inputs: dict) -> bool:
        """
        Verify a Zero-Knowledge Proof.
        
        Args:
            proof: The proof to verify
            public_inputs: Public inputs for verification
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            # Write proof to file
            proof_path = os.path.join(self.working_dir, "temp.proof.json")
            with open(proof_path, 'w') as f:
                json.dump(proof["proof"], f)
            
            # Verify proof
            result = self._run_zokrates_command(['verify'])
            return result.returncode == 0
        except Exception as e:
            print(f"Error verifying proof: {str(e)}")
            return False
    
    def _prepare_public_inputs(self, credential: dict) -> dict:
        """Prepare public inputs for proof generation."""
        return {
            "credential_id": credential["id"],
            "issuer": credential["issuer"],
            "expiration_date": credential["expirationDate"],
            "credential_type": credential["type"][1]
        }
    
    def _generate_proof_id(self, credential_id: str, proof_type: str) -> str:
        """Generate a unique proof ID."""
        # Use HKDF to generate a deterministic ID
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b'proof_id'
        )
        key = hkdf.derive(f"{credential_id}:{proof_type}".encode())
        return base64.b64encode(key).decode() 