from typing import Dict, Any, Optional
import json
import subprocess
import os
import platform
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
from datetime import datetime, timezone
import asyncio
import concurrent.futures
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import hashlib
from functools import lru_cache

class ZKPProver:
    """Zero-Knowledge Proof Prover for LVC-SSI Framework."""
    
    def __init__(self):
        """Initialize the ZKP prover with thread pool executor."""
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._circuit_cache = {}
        self._setup_cache = {}
        self._circuit_dir = Path(__file__).parent.parent / "circuits"
        self._circuit_dir.mkdir(exist_ok=True)
    
    def __del__(self):
        """Cleanup thread pool executor on deletion."""
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=True)
    
    @lru_cache(maxsize=32)
    def _get_file_hash(self, file_path: str) -> str:
        """Get hash of file contents for caching."""
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    async def _compile_circuit(self, circuit_name: str) -> str:
        """Compile a circuit using the thread pool."""
        circuit_path = self._circuit_dir / f"{circuit_name}.zok"
        if not circuit_path.exists():
            raise FileNotFoundError(f"Circuit file not found: {circuit_path}")
        
        # Check cache
        file_hash = self._get_file_hash(str(circuit_path))
        if file_hash in self._circuit_cache:
            return self._circuit_cache[file_hash]
        
        # Compile circuit
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            self._executor,
            lambda: os.system(f"zokrates compile -i {circuit_path}")
        )
        
        if result != 0:
            raise RuntimeError(f"Failed to compile circuit: {circuit_name}")
        
        self._circuit_cache[file_hash] = str(circuit_path)
        return str(circuit_path)
    
    async def _setup_circuit(self, circuit_name: str) -> str:
        """Set up a circuit using the thread pool."""
        circuit_path = await self._compile_circuit(circuit_name)
        
        # Check cache
        file_hash = self._get_file_hash(circuit_path)
        if file_hash in self._setup_cache:
            return self._setup_cache[file_hash]
        
        # Setup circuit
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            self._executor,
            lambda: os.system(f"zokrates setup -i {circuit_path}")
        )
        
        if result != 0:
            raise RuntimeError(f"Failed to setup circuit: {circuit_name}")
        
        self._setup_cache[file_hash] = str(circuit_path)
        return str(circuit_path)
    
    async def _compute_witness(self, circuit_name: str, inputs: Dict[str, Any]) -> str:
        """Compute witness using the thread pool."""
        circuit_path = await self._setup_circuit(circuit_name)
        witness_path = self._circuit_dir / f"{circuit_name}.wtns"
        
        # Convert inputs to witness format
        witness_inputs = []
        for key, value in inputs.items():
            if isinstance(value, (list, tuple)):
                witness_inputs.extend(value)
            else:
                witness_inputs.append(value)
        
        # Write witness inputs to file
        input_file = self._circuit_dir / f"{circuit_name}_input.json"
        with open(input_file, 'w') as f:
            json.dump(witness_inputs, f)
        
        # Compute witness
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            self._executor,
            lambda: os.system(f"zokrates compute-witness -i {circuit_path} -o {witness_path} -a {' '.join(map(str, witness_inputs))}")
        )
        
        if result != 0:
            raise RuntimeError(f"Failed to compute witness for circuit: {circuit_name}")
        
        return str(witness_path)
    
    async def generate_proof(self, credential: Dict[str, Any], proof_type: str, private_inputs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate a zero-knowledge proof."""
        try:
            print(f"Compiling circuit for {proof_type}...")
            circuit_path = await self._compile_circuit(proof_type)
            print(f"Circuit path: {circuit_path}")
            
            print(f"Setting up circuit for {proof_type}...")
            await self._setup_circuit(proof_type)
            
            # Prepare witness inputs
            witness_inputs = {
                "credential_id": credential["id"],
                "issuer": credential["issuer"],
                "expiration_date": credential["expirationDate"],
                "credential_type": credential["type"][1],
                **private_inputs
            }
            
            print(f"Computing witness...")
            witness_path = await self._compute_witness(proof_type, witness_inputs)
            print(f"Witness path: {witness_path}")
            
            # Generate proof
            proof_path = self._circuit_dir / "proof.json"
            print(f"Proof path: {proof_path}")
            
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self._executor,
                lambda: os.system(f"zokrates generate-proof -i {circuit_path} -w {witness_path} -p {proof_path}")
            )
            
            if result != 0:
                raise RuntimeError(f"Failed to generate proof for circuit: {proof_type}")
            
            # Read and return proof
            with open(proof_path, 'r') as f:
                proof = json.load(f)
            
            # Add metadata
            proof["metadata"] = {
                "credential_id": credential["id"],
                "proof_type": proof_type,
                "generated_at": str(datetime.now(timezone.utc))
            }
            
            return proof
            
        except Exception as e:
            print(f"Error generating proof: {str(e)}")
            return None
    
    async def verify_proof(self, proof: Dict[str, Any], public_inputs: Dict[str, Any]) -> bool:
        """Verify a zero-knowledge proof."""
        try:
            if not proof:
                return False
            
            circuit_name = proof.get("metadata", {}).get("proof_type", "access_control")
            circuit_path = await self._setup_circuit(circuit_name)
            
            # Write proof to file
            proof_path = self._circuit_dir / "proof.json"
            with open(proof_path, 'w') as f:
                json.dump(proof, f)
            
            # Verify proof
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self._executor,
                lambda: os.system(f"zokrates verify -i {circuit_path} -p {proof_path}")
            )
            
            return result == 0
            
        except Exception as e:
            print(f"Error verifying proof: {str(e)}")
            return False
    
    def _run_zokrates_command(self, command: list) -> subprocess.CompletedProcess:
        """Run a ZoKrates command using Docker."""
        docker_cmd = [
            'docker', 'run', '-v', f'{self._circuit_dir}:/home/zokrates/code',
            '-w', '/home/zokrates/code', 'zokrates/zokrates',
            '/home/zokrates/.zokrates/bin/zokrates'
        ] + command
        return subprocess.run(docker_cmd, check=True, capture_output=True, text=True)
    
    @lru_cache(maxsize=32)
    def _get_circuit_path(self, proof_type: str) -> Path:
        """Get the path for a specific circuit type with caching."""
        return self._circuit_dir / f"{proof_type}.zok"
    
    @lru_cache(maxsize=32)
    def _get_witness_path(self, proof_type: str) -> Path:
        """Get the path for a specific witness file with caching."""
        return self._circuit_dir / f"{proof_type}.wtns"
    
    @lru_cache(maxsize=32)
    def _get_proof_path(self, proof_type: str) -> Path:
        """Get the path for a specific proof file with caching."""
        return self._circuit_dir / f"{proof_type}_proof.json"
    
    async def _ensure_circuit_ready(self, proof_type: str) -> None:
        """Ensure circuit is compiled and setup is complete with caching."""
        circuit_path = self._get_circuit_path(proof_type)
        circuit_hash = self._get_file_hash(str(circuit_path))
        
        if circuit_hash not in self._circuit_cache:
            print(f"Compiling circuit for {proof_type}...")
            await self._compile_circuit(proof_type)
            self._circuit_cache[circuit_hash] = True
            
        if circuit_hash not in self._setup_cache:
            print(f"Setting up circuit for {proof_type}...")
            await self._setup_circuit(proof_type)
            self._setup_cache[circuit_hash] = True
    
    def _generate_proof_id(self, credential: Dict[str, Any], proof_type: str) -> str:
        """Generate a unique proof ID."""
        data = f"{credential['id']}:{proof_type}:{credential['issuanceDate']}"
        return hashlib.md5(data.encode()).digest().hex()[:16]
    
    def _prepare_public_inputs(self, credential: dict) -> dict:
        """Prepare public inputs for proof generation."""
        return {
            "credential_id": credential["id"],
            "issuer": credential["issuer"],
            "expiration_date": credential["expirationDate"],
            "credential_type": credential["type"][1]
        }
    
    async def _ensure_circuit_ready(self, proof_type: str):
        """Ensure circuit is compiled and setup is done."""
        with self._circuit_lock:
            if not self.compiled_circuits.get(proof_type):
                print(f"Compiling circuit for {proof_type}...")
                circuit_path = os.path.join(self._circuit_dir, f"{proof_type}.zok")
                await asyncio.get_event_loop().run_in_executor(
                    self._executor,
                    lambda: self._run_zokrates_command(['compile', '-i', os.path.basename(circuit_path)])
                )
                self.compiled_circuits[proof_type] = True
                
            if not self.setup_done.get(proof_type):
                print(f"Setting up circuit for {proof_type}...")
                await asyncio.get_event_loop().run_in_executor(
                    self._executor,
                    lambda: self._run_zokrates_command(['setup'])
                )
                self.setup_done[proof_type] = True

    async def generate_proof(self, 
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
            # Check cache first
            proof_id = self._generate_proof_id(credential["id"], proof_type)
            with self._proof_cache_lock:
                if proof_id in self.proof_cache:
                    return {
                        "proof_id": proof_id,
                        "proof_type": proof_type,
                        "credential_id": credential["id"],
                        "proof": self.proof_cache[proof_id]
                    }

            # Ensure circuit is ready
            await self._ensure_circuit_ready(proof_type)
            
            # Convert credential to proof inputs
            public_inputs = self._prepare_public_inputs(credential)
            
            # Prepare input files with absolute paths
            circuit_path = os.path.join(self._circuit_dir, f"{proof_type}.zok")
            witness_path = os.path.join(self._circuit_dir, f"{proof_type}.wtns")
            proof_path = os.path.join(self._circuit_dir, "proof.json")
            
            print(f"Circuit path: {circuit_path}")
            print(f"Witness path: {witness_path}")
            print(f"Proof path: {proof_path}")
            
            # Convert inputs to field elements (integers)
            hash_obj = hashes.Hash(hashes.SHA256())
            hash_obj.update(public_inputs["credential_id"].encode())
            credential_id_hash = int.from_bytes(hash_obj.finalize()[:8], byteorder='big')
            
            hash_obj = hashes.Hash(hashes.SHA256())
            hash_obj.update(public_inputs["issuer"].encode())
            issuer_hash = int.from_bytes(hash_obj.finalize()[:8], byteorder='big')
            
            expiration_timestamp = int(datetime.fromisoformat(public_inputs["expiration_date"]).timestamp())
            
            hash_obj = hashes.Hash(hashes.SHA256())
            hash_obj.update(public_inputs["credential_type"].encode())
            type_hash = int.from_bytes(hash_obj.finalize()[:8], byteorder='big')
            
            role_map = {"operator": 1, "commander": 2, "analyst": 3}
            clearance_map = {"low": 1, "medium": 2, "high": 3}
            
            role_value = role_map.get(private_inputs["role"], 0)
            clearance_value = clearance_map.get(private_inputs["clearance_level"], 0)
            
            witness_values = [
                str(credential_id_hash),
                str(issuer_hash),
                str(expiration_timestamp),
                str(type_hash),
                str(role_value),
                str(clearance_value)
            ]
            
            print("Witness values:", witness_values)
            
            # Run witness computation and proof generation in parallel
            loop = asyncio.get_event_loop()
            
            # Compute witness
            print("Computing witness...")
            witness_result = await loop.run_in_executor(
                self._executor,
                lambda: self._run_zokrates_command(['compute-witness', '-a'] + witness_values)
            )
            if witness_result.returncode != 0:
                print(f"Error computing witness: {witness_result.stderr}")
                return None
            
            # Generate proof
            print("Generating proof...")
            proof_result = await loop.run_in_executor(
                self._executor,
                lambda: self._run_zokrates_command(['generate-proof'])
            )
            if proof_result.returncode != 0:
                print(f"Error generating proof: {proof_result.stderr}")
                return None
            
            # Export verifier in parallel
            print("Exporting verifier...")
            await loop.run_in_executor(
                self._executor,
                lambda: self._run_zokrates_command(['export-verifier'])
            )
            
            # Read the proof
            if not os.path.exists(proof_path):
                print(f"Proof file not found at: {proof_path}")
                print("Checking for proof file in working directory...")
                print("Current directory contents:")
                print(os.listdir(self._circuit_dir))
                return None
                
            with open(proof_path, 'r') as f:
                proof = json.load(f)
            
            # Cache the proof
            with self._proof_cache_lock:
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
    
    async def verify_proof(self, 
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
            proof_path = os.path.join(self._circuit_dir, "temp.proof.json")
            with open(proof_path, 'w') as f:
                json.dump(proof["proof"], f)
            
            # Verify proof using thread pool
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self._executor,
                lambda: self._run_zokrates_command(['verify'])
            )
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