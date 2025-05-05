from src.did.did_manager import DIDManager
from src.vc.vc_manager import VCManager
from src.zkp.zkp_prover import ZKPProver
from src.sig.simulation_gateway import SimulationGateway
import json

def main():
    # Initialize components
    did_manager = DIDManager()
    vc_manager = VCManager()
    zkp_prover = ZKPProver()
    gateway = SimulationGateway()

    print("=== Testing LVC-SSI Framework ===\n")

    # 1. Create a DID for a simulation operator
    print("1. Creating DID for simulation operator...")
    operator_did, operator_doc = did_manager.create_did("simulation_operator")
    print(f"Created DID: {operator_did}")
    print(f"DID Document: {json.dumps(operator_doc, indent=2)}\n")

    # 2. Create a DID for the issuer (e.g., a commander)
    print("2. Creating DID for commander (issuer)...")
    commander_did, commander_doc = did_manager.create_did("commander")
    print(f"Created DID: {commander_did}\n")

    # 3. Issue a credential to the operator
    print("3. Issuing credential to operator...")
    credential = vc_manager.issue_credential(
        subject_did=operator_did,
        issuer_did=commander_did,
        credential_type="simulation_access",
        attributes={
            "role": "operator",
            "clearance_level": "high",
            "allowed_simulations": ["tactical", "strategic"]
        },
        private_key_pem=commander_doc["verificationMethod"][0]["publicKeyPem"],
        validity_days=30
    )
    print(f"Issued Credential: {json.dumps(credential, indent=2)}\n")

    # 4. Generate a ZKP for access control
    print("4. Generating ZKP for access control...")
    private_inputs = {
        "role": "operator",
        "clearance_level": "high"
    }
    proof = zkp_prover.generate_proof(
        credential=credential,
        proof_type="access_control",
        private_inputs=private_inputs
    )
    print(f"Generated Proof: {json.dumps(proof, indent=2)}\n")

    # 5. Test access control
    print("5. Testing access control...")
    # Add an access policy
    gateway.add_access_policy(
        resource_id="tactical_simulation",
        policy={
            "public_inputs": {
                "required_role": "operator",
                "required_clearance": "high"
            }
        }
    )

    # Test access request
    access_response = gateway.handle_access_request({
        "proof_id": proof["proof_id"],
        "resource_id": "tactical_simulation",
        "action": "execute"
    })
    print(f"Access Response: {json.dumps(access_response.dict(), indent=2)}\n")

    # 6. View access logs
    print("6. Access Logs:")
    logs = gateway.get_access_logs()
    print(json.dumps(logs, indent=2))

if __name__ == "__main__":
    main() 