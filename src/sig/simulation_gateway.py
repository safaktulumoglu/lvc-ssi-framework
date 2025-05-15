from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, Dict
import uvicorn
from datetime import datetime

from src.did.did_manager import DIDManager
from src.vc.vc_manager import VCManager
from src.zkp.zkp_prover import ZKPProver

class AccessRequest(BaseModel):
    proof_id: Optional[str] = None
    credential: Optional[dict] = None
    resource_id: str
    action: str

class AccessResponse(BaseModel):
    granted: bool
    reason: Optional[str] = None
    timestamp: str

class SimulationGateway:
    def __init__(self, zkp_prover=None):
        self.app = FastAPI(title="LVC-SSI Simulation Gateway")
        self.did_manager = DIDManager()
        self.vc_manager = VCManager()
        self.zkp_prover = zkp_prover if zkp_prover is not None else ZKPProver()
        self.access_policies: Dict[str, dict] = {}
        self.access_logs: list = []
        self.access_cache: Dict[str, tuple[bool, str]] = {}  # Cache for access decisions
        self.cache_ttl = 300  # Cache TTL in seconds
        
        # Setup routes
        self.app.post("/access/request", response_model=AccessResponse)(self.handle_access_request)
        self.app.get("/access/logs")(self.get_access_logs)
        
    def _get_cache_key(self, request: AccessRequest) -> str:
        """Generate a cache key for the access request."""
        if request.proof_id:
            return f"proof:{request.proof_id}:{request.resource_id}:{request.action}"
        else:
            return f"cred:{request.credential['id']}:{request.resource_id}:{request.action}"
            
    def _check_cache(self, cache_key: str) -> Optional[tuple[bool, str]]:
        """Check if the access decision is cached and valid."""
        if cache_key in self.access_cache:
            is_valid, reason = self.access_cache[cache_key]
            return is_valid, reason
        return None
        
    def _update_cache(self, cache_key: str, is_valid: bool, reason: str):
        """Update the access cache."""
        self.access_cache[cache_key] = (is_valid, reason)
        
    async def handle_access_request(self, request: AccessRequest) -> AccessResponse:
        """
        Handle an access request using either ZKP verification or credential verification.
        
        Args:
            request: Access request containing either proof_id or credential, and resource details
            
        Returns:
            AccessResponse: Result of the access request
        """
        # Get access policy for the resource
        policy = self.access_policies.get(request.resource_id)
        if not policy:
            return AccessResponse(
                granted=False,
                reason="No access policy found for resource",
                timestamp=datetime.utcnow().isoformat()
            )
        
        # Check cache first
        cache_key = self._get_cache_key(request)
        cached_result = self._check_cache(cache_key)
        if cached_result:
            is_valid, reason = cached_result
            return AccessResponse(
                granted=is_valid,
                reason=reason,
                timestamp=datetime.utcnow().isoformat()
            )
        
        is_valid = False
        reason = "Access denied"
        
        if request.proof_id:
            # ZKP-based access control
            print(f"Verifying proof with ID: {request.proof_id}")
            print(f"Available proof IDs: {list(self.zkp_prover.proof_cache.keys())}")
            
            proof = self.zkp_prover.proof_cache.get(request.proof_id)
            if not proof:
                return AccessResponse(
                    granted=False,
                    reason="Invalid proof ID",
                    timestamp=datetime.utcnow().isoformat()
                )
            
            # Verify the proof
            public_inputs = {
                "resource_id": request.resource_id,
                "action": request.action,
                **policy["public_inputs"]
            }
            
            print(f"Verifying proof with inputs: {public_inputs}")
            is_valid = self.zkp_prover.verify_proof(proof, public_inputs)
            reason = "Access granted" if is_valid else "Invalid proof"
            print(f"Proof verification result: {is_valid}")
            
        elif request.credential:
            # Credential-based access control
            try:
                # Get issuer's DID document
                issuer_doc = self.did_manager.resolve_did(request.credential["issuer"])
                if not issuer_doc:
                    return AccessResponse(
                        granted=False,
                        reason="Issuer's DID document not found",
                        timestamp=datetime.utcnow().isoformat()
                    )
                
                # Get issuer's public key
                issuer_public_key = issuer_doc["verificationMethod"][0]["publicKeyPem"]
                
                # Verify the credential
                is_valid = self.vc_manager.verify_credential(
                    request.credential,
                    issuer_public_key
                )
                
                if is_valid:
                    # Check if credential attributes match policy requirements
                    subject = request.credential["credentialSubject"]
                    required_role = policy["public_inputs"]["required_role"]
                    required_clearance = policy["public_inputs"]["required_clearance"]
                    
                    is_valid = (
                        subject.get("role") == required_role and
                        subject.get("clearance_level") == required_clearance
                    )
                    reason = "Access granted" if is_valid else "Credential attributes do not match policy"
            except Exception as e:
                is_valid = False
                reason = f"Credential verification failed: {str(e)}"
        
        # Update cache
        self._update_cache(cache_key, is_valid, reason)
        
        # Log the access attempt
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "proof_id": request.proof_id,
            "credential_id": request.credential["id"] if request.credential else None,
            "resource_id": request.resource_id,
            "action": request.action,
            "granted": is_valid,
            "reason": reason
        }
        self.access_logs.append(log_entry)
        print(f"Access log entry: {log_entry}")
        
        return AccessResponse(
            granted=is_valid,
            reason=reason,
            timestamp=datetime.utcnow().isoformat()
        )
    
    async def get_access_logs(self):
        """Get the access logs."""
        return self.access_logs
    
    def add_access_policy(self, resource_id: str, policy: dict):
        """Add an access policy for a resource."""
        self.access_policies[resource_id] = policy
    
    def run(self, host: str = "0.0.0.0", port: int = 8000):
        """Run the SIG server."""
        uvicorn.run(self.app, host=host, port=port)

if __name__ == "__main__":
    gateway = SimulationGateway()
    gateway.run() 