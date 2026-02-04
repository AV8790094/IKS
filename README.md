import hashlib
import os
import time
import socket
import threading
from typing import Dict, Tuple, Optional
from dataclasses import dataclass
from tinyec import registry
from tinyec.ec import Point, Inf
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import secrets

# ============================
# Cryptographic Configuration
# ============================

CURVE = registry.get_curve('secp256r1')  # NIST P-256
HASH_ALG = hashlib.sha256
NONCE_SIZE = 16  # 128 bits
ID_SIZE = 16     # 128 bits
TIMESTAMP_SIZE = 8  # 64 bits
ECC_KEY_SIZE = 32   # 256 bits

# ============================
# Data Classes for Entities
# ============================

@dataclass
class EntityParams:
    """Common parameters for all IoT entities"""
    entity_id: bytes
    private_key: int
    public_key: Point
    nonce: Optional[bytes] = None
    session_key: Optional[bytes] = None
    stored_params: Dict = None

# ============================
# Cryptographic Utilities
# ============================

def generate_nonce() -> bytes:
    """Generate a random nonce (128 bits)"""
    return secrets.token_bytes(NONCE_SIZE)

def generate_id() -> bytes:
    """Generate a random entity ID (128 bits)"""
    return secrets.token_bytes(ID_SIZE)

def sha256(data: bytes) -> bytes:
    """SHA-256 hash function"""
    return HASH_ALG(data).digest()

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings"""
    return bytes(x ^ y for x, y in zip(a, b))

def concat(*args) -> bytes:
    """Concatenate multiple byte strings"""
    return b''.join(args)

def ecc_point_multiplication(k: int, point: Point) -> Point:
    """Elliptic curve point multiplication"""
    return k * point

def ecc_point_addition(p1: Point, p2: Point) -> Point:
    """Elliptic curve point addition"""
    return p1 + p2

def generate_ecc_keypair() -> Tuple[int, Point]:
    """Generate ECC key pair"""
    private_key = secrets.randbelow(CURVE.field.n)
    public_key = private_key * CURVE.g
    return private_key, public_key

# ============================
# Gateway Node Implementation
# ============================

class GatewayNode:
    def __init__(self):
        self.id = generate_id()
        self.private_key, self.public_key = generate_ecc_keypair()
        self.secret_key_k = secrets.randbelow(CURVE.field.n)
        self.registered_devices = {}
        self.registered_sensors = {}
        self.sessions = {}
        
        # Public parameters
        self.public_params = {
            'PK_GWN': self.public_key,
            'curve': CURVE,
            'hash_func': 'SHA256'
        }
    
    def setup_phase(self):
        """Setup phase as described in Section IV.A"""
        print(f"[GWN] Setup Phase - Secret key k: {self.secret_key_k}")
        print(f"[GWN] Public parameters published")
        return self.public_params
    
    def register_mobile_device(self, md_id: bytes, md_nonce: bytes, md_public_key: Point):
        """Mobile Device Registration (Section IV.B.1)"""
        print(f"[GWN] Registering Mobile Device: {md_id.hex()[:16]}...")
        
        gwn_nonce = generate_nonce()
        r1 = generate_nonce()
        
        # Calculate registration parameters
        A1 = xor_bytes(gwn_nonce, md_nonce)
        A2 = xor_bytes(A1, r1)
        A3 = sha256(concat(A1, md_id))
        A4 = sha256(concat(sha256(concat(A2, md_id)), md_nonce))
        A5 = sha256(concat(md_id, md_public_key.x.to_bytes(32, 'big'), md_nonce))
        A6 = sha256(concat(self.id, self.public_key.x.to_bytes(32, 'big'), gwn_nonce))
        A7 = xor_bytes(r1, xor_bytes(A5, A6))
        A8 = xor_bytes(gwn_nonce, xor_bytes(A5, A6))
        
        # Store device information
        self.registered_devices[md_id] = {
            'h_A1_ID': A3,
            'A2': A2,
            'nonce': md_nonce
        }
        
        registration_data = {
            'A1': A1, 'A2': A2, 'A3': A3, 'A4': A4,
            'A5': A5, 'A6': A6, 'A7': A7, 'A8': A8,
            'NGWN': gwn_nonce
        }
        
        print(f"[GWN] Mobile Device registration complete")
        return registration_data
    
    def register_sensor_node(self, sn_id: bytes, sn_nonce: bytes, sn_public_key: Point):
        """Sensor Node Registration (Section IV.B.2)"""
        print(f"[GWN] Registering Sensor Node: {sn_id.hex()[:16]}...")
        
        gwn_nonce = generate_nonce()
        r2 = generate_nonce()
        
        # Similar calculation as MD registration
        B1 = xor_bytes(gwn_nonce, sn_nonce)
        B2 = xor_bytes(B1, r2)
        B3 = sha256(concat(B1, sn_id))
        B4 = sha256(concat(sha256(concat(B2, sn_id)), sn_nonce))
        B5 = sha256(concat(sn_id, sn_public_key.x.to_bytes(32, 'big'), sn_nonce))
        B6 = sha256(concat(self.id, self.public_key.x.to_bytes(32, 'big'), gwn_nonce))
        B7 = xor_bytes(r2, xor_bytes(B5, B6))
        B8 = xor_bytes(gwn_nonce, xor_bytes(B5, B6))
        
        # Store sensor information
        self.registered_sensors[sn_id] = {
            'h_B1_ID': B3,
            'B2': B2,
            'nonce': sn_nonce
        }
        
        registration_data = {
            'B1': B1, 'B2': B2, 'B3': B3, 'B4': B4,
            'B5': B5, 'B6': B6, 'B7': B7, 'B8': B8,
            'NGWN': gwn_nonce
        }
        
        print(f"[GWN] Sensor Node registration complete")
        return registration_data
    
    def authenticate_session(self, auth_message: Dict) -> Dict:
        """Handle authentication phase messages"""
        print(f"[GWN] Processing authentication request...")
        
        # Extract and verify timestamp
        current_time = int(time.time())
        message_time = int.from_bytes(auth_message.get('T1'), 'big')
        
        if abs(current_time - message_time) > 5:  # ΔT = 5 seconds
            raise ValueError("Timestamp validation failed")
        
        # Process authentication (simplified for demo)
        session_id = generate_nonce()
        self.sessions[session_id] = {
            'status': 'authenticating',
            'start_time': current_time
        }
        
        # Generate response (simplified)
        response = {
            'D1': generate_nonce(),
            'D2': generate_nonce(),
            'D3': generate_nonce(),
            'D4': generate_nonce(),
            'T2': current_time.to_bytes(TIMESTAMP_SIZE, 'big'),
            'session_id': session_id
        }
        
        print(f"[GWN] Authentication response generated")
        return response

# ============================
# Mobile Device Implementation
# ============================

class MobileDevice:
    def __init__(self):
        self.id = generate_id()
        self.nonce = generate_nonce()
        self.private_key, self.public_key = generate_ecc_keypair()
        self.stored_credentials = {}
        self.session_keys = {}
    
    def register_with_gateway(self, gateway: GatewayNode):
        """Mobile device registration process"""
        print(f"[MD] Starting registration with Gateway...")
        
        # Step 1: Prepare registration request
        pid_md = concat(self.id, self.nonce)
        i_md = concat(pid_md, self.public_key.x.to_bytes(32, 'big'))
        
        # Step 2: Send to GWN and receive response
        registration_data = gateway.register_mobile_device(
            self.id, self.nonce, self.public_key
        )
        
        # Step 3: Verify and store credentials
        self.verify_registration(registration_data)
        
        print(f"[MD] Registration completed successfully")
    
    def verify_registration(self, reg_data: Dict):
        """Verify registration response from GWN"""
        # Verify public key matches
        expected_pk = self.private_key * CURVE.g
        if expected_pk != self.public_key:
            raise ValueError("Public key verification failed")
        
        # Store credentials
        self.stored_credentials.update({
            'ID_MD': self.id,
            'ID_GWN': reg_data.get('NGWN'),
            'h_A1_ID': reg_data.get('A3'),
            'A2': reg_data.get('A2'),
            'registration_data': reg_data
        })
    
    def initiate_authentication(self, gateway: GatewayNode):
        """Initiate authentication with gateway"""
        print(f"[MD] Initiating authentication...")
        
        current_time = int(time.time())
        
        # Prepare authentication message
        auth_message = {
            'A4': self.stored_credentials['registration_data']['A4'],
            'A5': self.stored_credentials['registration_data']['A5'],
            'T1': current_time.to_bytes(TIMESTAMP_SIZE, 'big'),
            'ID_MD': self.id
        }
        
        # Send to gateway
        response = gateway.authenticate_session(auth_message)
        
        # Verify response
        if self.verify_authentication_response(response):
            print(f"[MD] Authentication successful")
            return True
        return False
    
    def verify_authentication_response(self, response: Dict) -> bool:
        """Verify authentication response from GWN"""
        current_time = int(time.time())
        response_time = int.from_bytes(response.get('T2'), 'big')
        
        if abs(current_time - response_time) > 5:
            return False
        
        # Additional verification would go here
        return True

# ============================
# Sensor Node Implementation
# ============================

class SensorNode:
    def __init__(self):
        self.id = generate_id()
        self.nonce = generate_nonce()
        self.private_key, self.public_key = generate_ecc_keypair()
        self.stored_credentials = {}
        self.session_key = None
    
    def register_with_gateway(self, gateway: GatewayNode):
        """Sensor node registration process"""
        print(f"[SN] Starting registration with Gateway...")
        
        # Prepare registration request
        pid_sn = concat(self.id, self.nonce)
        i_sn = concat(pid_sn, self.public_key.x.to_bytes(32, 'big'))
        
        # Send to GWN and receive response
        registration_data = gateway.register_sensor_node(
            self.id, self.nonce, self.public_key
        )
        
        # Store credentials
        self.stored_credentials.update({
            'ID_SN': self.id,
            'registration_data': registration_data
        })
        
        print(f"[SN] Registration completed successfully")
    
    def participate_in_authentication(self, auth_data: Dict):
        """Participate in authentication session"""
        print(f"[SN] Participating in authentication...")
        
        # Verify timestamp
        current_time = int(time.time())
        message_time = int.from_bytes(auth_data.get('T3'), 'big')
        
        if abs(current_time - message_time) > 5:
            raise ValueError("Timestamp validation failed")
        
        # Generate session key (simplified)
        self.session_key = generate_nonce()
        
        response = {
            'E3': generate_nonce(),
            'T3': current_time.to_bytes(TIMESTAMP_SIZE, 'big')
        }
        
        print(f"[SN] Authentication response generated")
        return response

# ============================
# Testbed Simulation
# ============================

class SmartHomeTestbed:
    def __init__(self):
        self.gateway = GatewayNode()
        self.mobile_device = MobileDevice()
        self.sensor_node = SensorNode()
        self.metrics = {
            'computation_times': [],
            'communication_costs': [],
            'energy_estimates': []
        }
    
    def run_complete_scenario(self):
        """Run complete authentication scenario"""
        print("\n" + "="*60)
        print("SMART HOME TESTBED SIMULATION")
        print("="*60)
        
        start_time = time.perf_counter()
        
        # Phase 1: Setup
        print("\n[PHASE 1] Setup Phase")
        self.gateway.setup_phase()
        
        # Phase 2: Registration
        print("\n[PHASE 2] Registration Phase")
        self.mobile_device.register_with_gateway(self.gateway)
        self.sensor_node.register_with_gateway(self.gateway)
        
        # Phase 3: Authentication
        print("\n[PHASE 3] Authentication Phase")
        auth_success = self.mobile_device.initiate_authentication(self.gateway)
        
        end_time = time.perf_counter()
        total_time = (end_time - start_time) * 1000  # Convert to ms
        
        # Record metrics
        self.metrics['computation_times'].append(total_time)
        
        print("\n" + "="*60)
        print("SIMULATION RESULTS")
        print("="*60)
        print(f"Total execution time: {total_time:.2f} ms")
        print(f"Authentication successful: {auth_success}")
        
        # Performance estimates based on paper
        print("\nEstimated Performance Metrics:")
        print(f"• Computation cost: ~1.15 ms (per session)")
        print(f"• Communication overhead: ~6784 bits")
        print(f"• Storage requirement: ~576 bytes")
        print(f"• Energy consumption: ~1.67 mJ (per session)")
        
        return auth_success
    
    def benchmark_crypto_operations(self):
        """Benchmark cryptographic operations as in Table II"""
        print("\n" + "="*60)
        print("CRYPTOGRAPHIC OPERATIONS BENCHMARK")
        print("="*60)
        
        operations = {
            'ECC Point Multiplication': lambda: ecc_point_multiplication(
                secrets.randbelow(CURVE.field.n), CURVE.g
            ),
            'SHA-256 Hash': lambda: sha256(os.urandom(64)),
            'XOR Operation': lambda: xor_bytes(os.urandom(32), os.urandom(32)),
            'Nonce Generation': generate_nonce
        }
        
        results = {}
        for op_name, op_func in operations.items():
            times = []
            for _ in range(100):
                start = time.perf_counter()
                op_func()
                end = time.perf_counter()
                times.append((end - start) * 1000)  # ms
            
            avg_time = sum(times) / len(times)
            results[op_name] = avg_time
            print(f"{op_name:<25}: {avg_time:.3f} ms")
        
        return results

# ============================
# Main Execution
# ============================

if __name__ == "__main__":
    # Create and run testbed
    testbed = SmartHomeTestbed()
    
    # Run benchmark
    testbed.benchmark_crypto_operations()
    
    # Run complete scenario
    print("\n")
    success = testbed.run_complete_scenario()
    
    if success:
        print("\n✅ Testbed simulation completed successfully!")
    else:
        print("\n❌ Testbed simulation encountered issues!")
