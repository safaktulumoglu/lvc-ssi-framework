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
        self._proof_cache_lock = threading.Lock()
        self._circuit_lock = threading.Lock()
        self.compiled_circuits = {}
        self.setup_done = {}
        self.proof_cache = {}
        self._witness_cache = {}
        self._verifier_cache = {}
        self._timeout = 30  # Default timeout in seconds
        
        # Ensure Docker is available
        try:
            subprocess.run(['docker', '--version'], check=True, capture_output=True, timeout=5)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("Docker is required but not found. Please install Docker first.")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Docker check timed out. Please ensure Docker is running.")
        
        # Pull ZoKrates image if not present
        try:
            subprocess.run(['docker', 'pull', 'zokrates/zokrates'], check=True, capture_output=True, timeout=60)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to pull ZoKrates Docker image: {e.stderr.decode()}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Docker pull timed out. Please check your internet connection.")
    
    def __del__(self):
        """Cleanup thread pool executor on deletion."""
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=True)
    
    @lru_cache(maxsize=32)
    def _get_file_hash(self, file_path: str) -> str:
        """Get hash of file contents for caching."""
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    def _run_zokrates_command(self, command: list) -> subprocess.CompletedProcess:
        """Run a ZoKrates command using Docker with timeout."""
        docker_cmd = [
            'docker', 'run', '-v', f'{self._circuit_dir}:/home/zokrates/code',
            '-w', '/home/zokrates/code', 'zokrates/zokrates',
            '/home/zokrates/.zokrates/bin/zokrates'
        ] + command
        try:
            return subprocess.run(docker_cmd, check=True, capture_output=True, text=True, timeout=self._timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"ZoKrates command timed out after {self._timeout} seconds")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"ZoKrates command failed: {e.stderr}")
    
    async def _compile_circuit(self, circuit_name: str) -> str:
        """Compile a circuit using Docker with enhanced caching and timeout."""
        circuit_path = self._circuit_dir / f"{circuit_name}.zok"
        if not circuit_path.exists():
            raise FileNotFoundError(f"Circuit file not found: {circuit_path}")
        
        # Check cache with file hash
        file_hash = self._get_file_hash(str(circuit_path))
        if file_hash in self._circuit_cache:
            return self._circuit_cache[file_hash]
        
        # Use circuit lock for thread safety with timeout
        try:
            with self._circuit_lock:
                if file_hash in self._circuit_cache:
                    return self._circuit_cache[file_hash]
                
                # Compile circuit using Docker
                loop = asyncio.get_event_loop()
                try:
                    result = await asyncio.wait_for(
                        loop.run_in_executor(
                            self._executor,
                            lambda: self._run_zokrates_command(['compile', '-i', circuit_path.name])
                        ),
                        timeout=self._timeout
                    )
                    if result.returncode != 0:
                        raise RuntimeError(f"Failed to compile circuit: {result.stderr}")
                    
                    self._circuit_cache[file_hash] = str(circuit_path)
                    return str(circuit_path)
                except asyncio.TimeoutError:
                    raise RuntimeError(f"Circuit compilation timed out after {self._timeout} seconds")
        except Exception as e:
            raise RuntimeError(f"Error compiling circuit: {str(e)}")
    
    async def _setup_circuit(self, circuit_name: str) -> str:
        """Set up a circuit using Docker with enhanced caching and timeout."""
        try:
            circuit_path = await self._compile_circuit(circuit_name)
            
            # Check cache with file hash
            file_hash = self._get_file_hash(circuit_path)
            if file_hash in self._setup_cache:
                return self._setup_cache[file_hash]
            
            # Use circuit lock for thread safety with timeout
            with self._circuit_lock:
                if file_hash in self._setup_cache:
                    return self._setup_cache[file_hash]
                
                # Setup circuit using Docker
                loop = asyncio.get_event_loop()
                try:
                    result = await asyncio.wait_for(
                        loop.run_in_executor(
                            self._executor,
                            lambda: self._run_zokrates_command(['setup'])
                        ),
                        timeout=self._timeout
                    )
                    if result.returncode != 0:
                        raise RuntimeError(f"Failed to setup circuit: {result.stderr}")
                    
                    self._setup_cache[file_hash] = str(circuit_path)
                    return str(circuit_path)
                except asyncio.TimeoutError:
                    raise RuntimeError(f"Circuit setup timed out after {self._timeout} seconds")
        except Exception as e:
            raise RuntimeError(f"Error setting up circuit: {str(e)}")
    
    async def _compute_witness(self, circuit_name: str, inputs: Dict[str, Any]) -> str:
        """Compute witness using Docker with caching."""
        circuit_path = await self._setup_circuit(circuit_name)
        witness_path = self._circuit_dir / f"{circuit_name}.wtns"
        
        # Generate cache key from inputs
        input_hash = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
        cache_key = f"{circuit_name}:{input_hash}"
        
        # Check witness cache
        if cache_key in self._witness_cache:
            return self._witness_cache[cache_key]
        
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
        
        # Compute witness using Docker
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                self._executor,
                lambda: self._run_zokrates_command([
                    'compute-witness',
                    '-i', circuit_path.name,
                    '-o', witness_path.name,
                    '-a'
                ] + [str(x) for x in witness_inputs])
            )
            if result.returncode != 0:
                raise RuntimeError(f"Failed to compute witness: {result.stderr}")
            
            self._witness_cache[cache_key] = str(witness_path)
            return str(witness_path)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to compute witness: {e.stderr}")
    
    async def generate_proof(self, credential: Dict[str, Any], proof_type: str, private_inputs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate a zero-knowledge proof with optimized caching and timeout handling."""
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
            
            # Prepare inputs
            public_inputs = self._prepare_public_inputs(credential)
            witness_inputs = {**public_inputs, **private_inputs}
            
            # Run circuit compilation, setup, and witness computation in parallel with timeout
            try:
                circuit_task = asyncio.create_task(self._compile_circuit(proof_type))
                setup_task = asyncio.create_task(self._setup_circuit(proof_type))
                witness_task = asyncio.create_task(self._compute_witness(proof_type, witness_inputs))
                
                # Wait for all tasks to complete with timeout
                circuit_path, setup_path, witness_path = await asyncio.wait_for(
                    asyncio.gather(circuit_task, setup_task, witness_task),
                    timeout=self._timeout * 3  # Allow more time for parallel operations
                )
            except asyncio.TimeoutError:
                raise RuntimeError(f"Proof generation timed out after {self._timeout * 3} seconds")
            except Exception as e:
                raise RuntimeError(f"Error during proof generation setup: {str(e)}")
            
            # Generate proof using Docker
            proof_path = self._circuit_dir / "proof.json"
            loop = asyncio.get_event_loop()
            try:
                result = await asyncio.wait_for(
                    loop.run_in_executor(
                        self._executor,
                        lambda: self._run_zokrates_command([
                            'generate-proof',
                            '-i', circuit_path.name,
                            '-w', witness_path.name,
                            '-p', proof_path.name
                        ])
                    ),
                    timeout=self._timeout
                )
                if result.returncode != 0:
                    raise RuntimeError(f"Failed to generate proof: {result.stderr}")
                
                # Read and return proof
                with open(proof_path, 'r') as f:
                    proof = json.load(f)
                
                # Add metadata
                proof["metadata"] = {
                    "credential_id": credential["id"],
                    "proof_type": proof_type,
                    "generated_at": str(datetime.now(timezone.utc))
                }
                
                # Cache the proof
                with self._proof_cache_lock:
                    self.proof_cache[proof_id] = proof
                
                return {
                    "proof_id": proof_id,
                    "proof_type": proof_type,
                    "credential_id": credential["id"],
                    "proof": proof
                }
            except asyncio.TimeoutError:
                raise RuntimeError(f"Proof generation timed out after {self._timeout} seconds")
            except Exception as e:
                raise RuntimeError(f"Error generating proof: {str(e)}")
            
        except Exception as e:
            print(f"Error generating proof: {str(e)}")
            return None
    
    async def verify_proof(self, proof: Dict[str, Any], public_inputs: Dict[str, Any]) -> bool:
        """Verify a zero-knowledge proof with optimized caching."""
        try:
            if not proof:
                return False
            
            circuit_name = proof.get("metadata", {}).get("proof_type", "access_control")
            
            # Check verifier cache
            verifier_key = f"{circuit_name}:{proof['proof_id']}"
            if verifier_key in self._verifier_cache:
                return True
            
            # Ensure circuit is ready
            await self._ensure_circuit_ready(circuit_name)
            
            # Write proof to file
            proof_path = self._circuit_dir / "proof.json"
            with open(proof_path, 'w') as f:
                json.dump(proof["proof"], f)
            
            # Verify proof using Docker
            loop = asyncio.get_event_loop()
            try:
                result = await loop.run_in_executor(
                    self._executor,
                    lambda: self._run_zokrates_command([
                        'verify',
                        '-i', self._get_circuit_path(circuit_name).name,
                        '-p', proof_path.name
                    ])
                )
                if result.returncode == 0:
                    # Cache successful verification
                    self._verifier_cache[verifier_key] = True
                    return True
                return False
            except subprocess.CalledProcessError as e:
                print(f"Error verifying proof: {e.stderr}")
                return False
            
        except Exception as e:
            print(f"Error verifying proof: {str(e)}")
            return False
    
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