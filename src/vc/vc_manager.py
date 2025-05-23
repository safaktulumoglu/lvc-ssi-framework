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
import time
import asyncio
import concurrent.futures
import threading

class VCManager:
    def __init__(self):
        self.issued_vcs: Dict[str, dict] = {}
        self.revoked_vcs: set = set()
        self.verification_cache: Dict[str, tuple[bool, float]] = {}  # Cache with timestamp
        self.cache_ttl = 300  # Cache TTL in seconds
        self._cache_lock = threading.Lock()
        self._storage_lock = threading.Lock()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        
    async def issue_credential(self, 
                             subject_did: str,
                             issuer_did: str,
                             credential_type: str,
                             attributes: dict,
                             private_key_pem: str,
                             validity_days: int = 30) -> dict:
        """
        Issue a Verifiable Credential.
        """
        try:
            # Generate credential ID
            credential_id = f"vc:{subject_did}:{credential_type}:{int(time.time())}"
            
            # Calculate expiration date
            expiration_date = (datetime.utcnow() + timedelta(days=validity_days)).isoformat()
            
            # Create credential
            credential = {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "id": credential_id,
                "type": ["VerifiableCredential", credential_type],
                "issuer": issuer_did,
                "issuanceDate": datetime.utcnow().isoformat(),
                "expirationDate": expiration_date,
                "credentialSubject": {
                    "id": subject_did,
                    **attributes
                }
            }
            
            # Sign the credential in parallel
            loop = asyncio.get_event_loop()
            
            # Load private key
            private_key = await loop.run_in_executor(
                self._executor,
                lambda: serialization.load_pem_private_key(
                    private_key_pem.encode(),
                    password=None,
                    backend=default_backend()
                )
            )
            
            # Create JWT
            header = {
                "alg": "RS256",
                "typ": "JWT"
            }
            
            payload = {
                "iss": issuer_did,
                "sub": subject_did,
                "iat": int(time.time()),
                "exp": int(datetime.fromisoformat(expiration_date).timestamp()),
                "jti": credential_id,
                "vc": credential
            }
            
            # Encode and sign in parallel
            encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            
            message = f"{encoded_header}.{encoded_payload}"
            
            # Sign the message
            signature = await loop.run_in_executor(
                self._executor,
                lambda: private_key.sign(
                    message.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    algorithm=hashes.SHA256()
                )
            )
            
            encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip('=')
            
            # Add proof
            credential["proof"] = {
                "type": "RsaSignature2018",
                "created": datetime.utcnow().isoformat(),
                "proofPurpose": "assertionMethod",
                "verificationMethod": f"{issuer_did}#keys-1",
                "jwt": f"{message}.{encoded_signature}"
            }
            
            # Store credential
            with self._storage_lock:
                self.issued_vcs[credential_id] = credential
            
            return credential
            
        except Exception as e:
            print(f"Error issuing credential: {str(e)}")
            raise
            
    async def verify_credential(self, credential: dict, issuer_public_key_pem: str) -> bool:
        """
        Verify a Verifiable Credential.
        """
        # Check cache first
        cache_key = f"{credential['id']}:{issuer_public_key_pem}"
        with self._cache_lock:
            if cache_key in self.verification_cache:
                is_valid, timestamp = self.verification_cache[cache_key]
                if time.time() - timestamp < self.cache_ttl:
                    return is_valid
                else:
                    del self.verification_cache[cache_key]  # Remove expired cache entry
        
        # Check if credential is revoked
        if credential["id"] in self.revoked_vcs:
            with self._cache_lock:
                self.verification_cache[cache_key] = (False, time.time())
            return False
        
        # Check expiration
        if datetime.fromisoformat(credential["expirationDate"]) < datetime.utcnow():
            with self._cache_lock:
                self.verification_cache[cache_key] = (False, time.time())
            return False
        
        try:
            # Load public key and verify JWT in parallel
            loop = asyncio.get_event_loop()
            
            # Load public key
            public_key = await loop.run_in_executor(
                self._executor,
                lambda: serialization.load_pem_public_key(
                    issuer_public_key_pem.encode(),
                    backend=default_backend()
                )
            )
            
            # Verify JWT signature
            token = credential["proof"]["jwt"]
            payload = await loop.run_in_executor(
                self._executor,
                lambda: jwt.decode(
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
            )
            
            # Verify payload matches credential
            is_valid = payload["id"] == credential["id"]
            with self._cache_lock:
                self.verification_cache[cache_key] = (is_valid, time.time())
            return is_valid
            
        except Exception:
            with self._cache_lock:
                self.verification_cache[cache_key] = (False, time.time())
            return False
    
    async def revoke_credential(self, credential_id: str) -> bool:
        """
        Revoke a Verifiable Credential.
        """
        with self._storage_lock:
            if credential_id in self.issued_vcs:
                self.revoked_vcs.add(credential_id)
                return True
        return False 