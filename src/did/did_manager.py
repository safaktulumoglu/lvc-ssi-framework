from typing import Dict, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import json
import base58

class DIDManager:
    def __init__(self):
        self.did_documents: Dict[str, dict] = {}
        
    def create_did(self, participant_type: str) -> tuple[str, dict]:
        """
        Create a new DID and its associated document.
        
        Args:
            participant_type: Type of participant (e.g., 'simulation_operator', 'commander')
            
        Returns:
            tuple: (DID string, DID document)
        """
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Get public key in PEM format
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Create DID (using a simple method for demonstration)
        did = f"did:lvc:{base58.b58encode(public_pem[:16]).decode()}"
        
        # Create DID document
        did_document = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": did,
            "verificationMethod": [{
                "id": f"{did}#keys-1",
                "type": "RsaVerificationKey2018",
                "controller": did,
                "publicKeyPem": public_pem.decode()
            }],
            "authentication": [f"{did}#keys-1"],
            "assertionMethod": [f"{did}#keys-1"],
            "participantType": participant_type
        }
        
        # Store DID document
        self.did_documents[did] = did_document
        
        return did, did_document
    
    def resolve_did(self, did: str) -> Optional[dict]:
        """
        Resolve a DID to its document.
        
        Args:
            did: The DID to resolve
            
        Returns:
            dict: The DID document if found, None otherwise
        """
        return self.did_documents.get(did)
    
    def revoke_did(self, did: str) -> bool:
        """
        Revoke a DID.
        
        Args:
            did: The DID to revoke
            
        Returns:
            bool: True if successful, False otherwise
        """
        if did in self.did_documents:
            del self.did_documents[did]
            return True
        return False 