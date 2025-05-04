# LVC-SSI Framework

A decentralized identity and access control framework for Live, Virtual, and Constructive (LVC) simulation environments based on Self-Sovereign Identity (SSI) principles.

## Overview

This framework implements a secure identity management system using:
- Decentralized Identifiers (DIDs)
- Verifiable Credentials (VCs)
- Zero-Knowledge Proofs (ZKPs)
- Smart Contracts for access control
- Simulation Integration Gateway (SIG)

## Architecture

The system consists of the following components:

1. **DID Management**: W3C-compliant DID implementation for unique participant identification
2. **VC Issuance**: Secure credential issuance and verification system
3. **ZKP System**: Privacy-preserving proof system for access verification
4. **Smart Contracts**: Access control policies and logging
5. **SIG**: Middleware for simulation environment integration

## Installation

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Start the DID registry:
   ```bash
   python src/did_registry.py
   ```

2. Start the VC issuer:
   ```bash
   python src/vc_issuer.py
   ```

3. Start the SIG:
   ```bash
   python src/sig.py
   ```

## Security Considerations

- All cryptographic operations use industry-standard algorithms
- Private keys are never stored in plaintext
- ZKPs ensure minimal data exposure
- Smart contracts are audited for security vulnerabilities

## License

This project is licensed under the MIT License - see the LICENSE file for details. 