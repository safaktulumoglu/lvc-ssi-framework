from typing import Dict, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import json
import base58
import didkit
import base64
import os

class DIDManager:
    def __init__(self):
        self.storage_file = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'did_documents.json')
        self.did_documents: Dict[str, dict] = {}
        self.did_cache: Dict[str, dict] = {}  # In-memory cache for DID documents
        self._load_documents()
        
    def _load_documents(self):
        """Load DID documents from storage file."""
        try:
            if os.path.exists(self.storage_file):
                with open(self.storage_file, 'r') as f:
                    self.did_documents = json.load(f)
                    self.did_cache = self.did_documents.copy()  # Initialize cache
        except Exception as e:
            print(f"Error loading DID documents: {str(e)}")
            self.did_documents = {}
            self.did_cache = {}
            
    def _save_documents(self):
        """Save DID documents to storage file."""
        try:
            os.makedirs(os.path.dirname(self.storage_file), exist_ok=True)
            with open(self.storage_file, 'w') as f:
                json.dump(self.did_documents, f, indent=2)
        except Exception as e:
            print(f"Error saving DID documents: {str(e)}")
            raise
            
    def create_did(self, participant_type: str) -> tuple[str, dict]:
        """
        Create a new DID and its associated document.
        
        Args:
            participant_type: Type of participant (e.g., 'simulation_operator', 'commander')
            
        Returns:
            tuple: (DID string, DID document)
        """
        try:
            # Generate RSA key pair with optimized parameters
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
            
            # Get private key in PEM format
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Convert public key to JWK format
            public_numbers = public_key.public_numbers()
            jwk = {
                "kty": "RSA",
                "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('='),
                "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=')
            }
            
            # Create DID using didkit
            did = didkit.key_to_did("key", json.dumps(jwk))
            
            # Create DID document
            did_document = {
                "@context": "https://www.w3.org/ns/did/v1",
                "id": did,
                "verificationMethod": [{
                    "id": f"{did}#keys-1",
                    "type": "RsaVerificationKey2018",
                    "controller": did,
                    "publicKeyPem": public_pem.decode(),
                    "privateKeyPem": private_pem.decode()
                }],
                "authentication": [f"{did}#keys-1"],
                "assertionMethod": [f"{did}#keys-1"],
                "participantType": participant_type
            }
            
            # Store DID document in both cache and storage
            self.did_documents[did] = did_document
            self.did_cache[did] = did_document
            self._save_documents()
            
            return did, did_document
            
        except Exception as e:
            print(f"Error creating DID: {str(e)}")
            raise
    
    def resolve_did(self, did: str) -> Optional[dict]:
        """
        Resolve a DID to its document.
        
        Args:
            did: The DID to resolve
            
        Returns:
            dict: The DID document if found, None otherwise
        """
        # Try cache first
        doc = self.did_cache.get(did)
        if doc:
            return doc
            
        # Try memory
        doc = self.did_documents.get(did)
        if doc:
            self.did_cache[did] = doc  # Update cache
            return doc
            
        # If not found, try to load from storage
        try:
            self._load_documents()
            doc = self.did_documents.get(did)
            if doc:
                self.did_cache[did] = doc  # Update cache
            return doc
        except Exception as e:
            print(f"Error resolving DID: {str(e)}")
            return None
    
    def revoke_did(self, did: str) -> bool:
        """
        Revoke a DID.
        
        Args:
            did: The DID to revoke
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if did in self.did_documents:
                del self.did_documents[did]
                self._save_documents()
                return True
            return False
        except Exception as e:
            print(f"Error revoking DID: {str(e)}")
            return False 