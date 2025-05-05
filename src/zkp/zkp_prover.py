from typing import Dict, Any
import json
from zokrates_pycrypto import zokrates
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64

class ZKPProver:
    def __init__(self):
        self.proof_cache: Dict[str, Any] = {}
        
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
        # Convert credential to proof inputs
        public_inputs = self._prepare_public_inputs(credential)
        
        # Generate proof using ZoKrates
        try:
            # Compile the circuit if not already compiled
            zokrates.compile(f"circuits/{proof_type}.zok")
            
            # Setup the circuit
            zokrates.setup()
            
            # Compute witness
            zokrates.compute_witness(public_inputs, private_inputs)
            
            # Generate proof
            proof = zokrates.generate_proof()
            
            # Cache the proof
            proof_id = self._generate_proof_id(credential["id"], proof_type)
            self.proof_cache[proof_id] = proof
            
            return {
                "proof_id": proof_id,
                "proof_type": proof_type,
                "credential_id": credential["id"],
                "proof": proof
            }
        except Exception as e:
            print(f"Error generating proof: {str(e)}")
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
            return zokrates.verify_proof(proof["proof"], public_inputs)
        except Exception:
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