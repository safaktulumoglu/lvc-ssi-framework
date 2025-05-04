from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, Dict
import uvicorn
from datetime import datetime

from ..did.did_manager import DIDManager
from ..vc.vc_manager import VCManager
from ..zkp.zkp_prover import ZKPProver

class AccessRequest(BaseModel):
    proof_id: str
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
        Handle an access request using ZKP verification.
        
        Args:
            request: Access request containing proof and resource details
            
        Returns:
            AccessResponse: Result of the access request
        """
        # Get the proof from cache
        proof = self.zkp_prover.proof_cache.get(request.proof_id)
        if not proof:
            return AccessResponse(
                granted=False,
                reason="Invalid proof ID",
                timestamp=datetime.utcnow().isoformat()
            )
        
        # Get access policy for the resource
        policy = self.access_policies.get(request.resource_id)
        if not policy:
            return AccessResponse(
                granted=False,
                reason="No access policy found for resource",
                timestamp=datetime.utcnow().isoformat()
            )
        
        # Verify the proof
        public_inputs = {
            "resource_id": request.resource_id,
            "action": request.action,
            **policy["public_inputs"]
        }
        
        is_valid = self.zkp_prover.verify_proof(proof, public_inputs)
        
        # Log the access attempt
        self.access_logs.append({
            "timestamp": datetime.utcnow().isoformat(),
            "proof_id": request.proof_id,
            "resource_id": request.resource_id,
            "action": request.action,
            "granted": is_valid
        })
        
        return AccessResponse(
            granted=is_valid,
            reason="Access granted" if is_valid else "Access denied",
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