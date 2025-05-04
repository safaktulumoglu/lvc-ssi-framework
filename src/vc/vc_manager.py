from typing import Dict, Optional
from datetime import datetime, timedelta
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class VCManager:
    def __init__(self):
        self.issued_vcs: Dict[str, dict] = {}
        self.revoked_vcs: set = set()
        
    def issue_credential(self, 
                        subject_did: str, 
                        issuer_did: str,
                        credential_type: str,
                        attributes: dict,
                        private_key_pem: str,
                        validity_days: int = 365) -> dict:
        """
        Issue a new Verifiable Credential.
        
        Args:
            subject_did: DID of the credential subject
            issuer_did: DID of the credential issuer
            credential_type: Type of credential (e.g., 'simulation_access')
            attributes: Dictionary of credential attributes
            private_key_pem: PEM-encoded private key of the issuer
            validity_days: Number of days the credential is valid
            
        Returns:
            dict: The issued Verifiable Credential
        """
        # Create credential ID
        credential_id = f"vc:{base64.b64encode(subject_did.encode()).decode()[:16]}"
        
        # Create credential payload
        now = datetime.utcnow()
        payload = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": credential_id,
            "type": ["VerifiableCredential", credential_type],
            "issuer": issuer_did,
            "issuanceDate": now.isoformat(),
            "expirationDate": (now + timedelta(days=validity_days)).isoformat(),
            "credentialSubject": {
                "id": subject_did,
                **attributes
            }
        }
        
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Sign the credential using JWT
        token = jwt.encode(
            payload,
            private_key,
            algorithm='RS256',
            headers={
                'typ': 'JWT',
                'alg': 'RS256',
                'kid': f"{issuer_did}#keys-1"
            }
        )
        
        # Create the final credential
        credential = {
            **payload,
            "proof": {
                "type": "JwtProof2020",
                "jwt": token
            }
        }
        
        # Store the credential
        self.issued_vcs[credential_id] = credential
        
        return credential
    
    def verify_credential(self, credential: dict, issuer_public_key_pem: str) -> bool:
        """
        Verify a Verifiable Credential.
        
        Args:
            credential: The Verifiable Credential to verify
            issuer_public_key_pem: PEM-encoded public key of the issuer
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Check if credential is revoked
        if credential["id"] in self.revoked_vcs:
            return False
        
        # Check expiration
        if datetime.fromisoformat(credential["expirationDate"]) < datetime.utcnow():
            return False
        
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                issuer_public_key_pem.encode(),
                backend=default_backend()
            )
            
            # Verify JWT signature
            token = credential["proof"]["jwt"]
            payload = jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                options={
                    'verify_exp': False,  # We already checked expiration
                    'verify_iat': True,
                    'verify_iss': True,
                    'verify_aud': False
                }
            )
            
            # Verify payload matches credential
            return payload["id"] == credential["id"]
            
        except Exception:
            return False
    
    def revoke_credential(self, credential_id: str) -> bool:
        """
        Revoke a Verifiable Credential.
        
        Args:
            credential_id: ID of the credential to revoke
            
        Returns:
            bool: True if successful, False otherwise
        """
        if credential_id in self.issued_vcs:
            self.revoked_vcs.add(credential_id)
            return True
        return False 