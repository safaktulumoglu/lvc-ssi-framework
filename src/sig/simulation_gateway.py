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
    def __init__(self):
        self.app = FastAPI(title="LVC-SSI Simulation Gateway")
        self.did_manager = DIDManager()
        self.vc_manager = VCManager()
        self.zkp_prover = ZKPProver()
        self.access_policies: Dict[str, dict] = {}
        self.access_logs: list = []
        
        # Setup routes
        self.app.post("/access/request", response_model=AccessResponse)(self.handle_access_request)
        self.app.get("/access/logs")(self.get_access_logs)
        
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
        
        is_valid = False
        reason = "Access denied"
        
        if request.proof_id:
            # ZKP-based access control
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
            
            is_valid = self.zkp_prover.verify_proof(proof, public_inputs)
            reason = "Access granted" if is_valid else "Invalid proof"
            
        elif request.credential:
            # Credential-based access control
            try:
                # Verify the credential
                is_valid = self.vc_manager.verify_credential(
                    request.credential,
                    self.did_manager.resolve_did(request.credential["issuer"])["verificationMethod"][0]["publicKeyPem"]
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
        
        # Log the access attempt
        self.access_logs.append({
            "timestamp": datetime.utcnow().isoformat(),
            "proof_id": request.proof_id,
            "credential_id": request.credential["id"] if request.credential else None,
            "resource_id": request.resource_id,
            "action": request.action,
            "granted": is_valid,
            "reason": reason
        })
        
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