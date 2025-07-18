#!/usr/bin/env python3

import os
import sys
import json
import argparse
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import re
import socket
import http.client
import urllib.parse
import ssl

from eth_keys import keys
from eth_utils import keccak

from typing import Optional, Dict, List, Tuple, Union, BinaryIO, Any

# Default whitelist file location
DEFAULT_KMS_WHITELIST_PATH = os.path.expanduser(
    "~/.dstack-vmm/kms-whitelist.json")


def encrypt_env(envs, hex_public_key: str) -> str:
    """
    Encrypts environment variables using a one-time X25519 key exchange and AES-GCM.

    This function does the following:
      1. Converts the given environment variables to JSON bytes.
      2. Removes a leading "0x" from the provided public key (if present) and converts it to bytes.
      3. Generates an ephemeral X25519 key pair.
      4. Computes a shared secret using this ephemeral private key and the remote public key.
      5. Uses the shared key directly as the 32-byte key for AES-GCM.
      6. Encrypts the JSON string with AES-GCM using a randomly generated IV.
      7. Concatenates the ephemeral public key, IV, and ciphertext and returns it as a hex string.

    Args:
        envs: The environment variables to encrypt. This can be any JSON-serializable data structure.
        hex_public_key: The remote encryption public key in hexadecimal format.

    Returns:
        A hexadecimal string that is the concatenation of:
          (ephemeral public key || IV || ciphertext).
    """
    # Serialize the environment variables to JSON and encode to bytes.
    envs_json = json.dumps({"env": envs}).encode("utf-8")

    # Remove the "0x" prefix if present.
    if hex_public_key.startswith("0x"):
        hex_public_key = hex_public_key[2:]

    # Convert the hexadecimal public key to bytes.
    remote_pubkey_bytes = bytes.fromhex(hex_public_key)

    # Generate an ephemeral X25519 key pair.
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Compute the shared secret using X25519.
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(
        remote_pubkey_bytes)
    shared = ephemeral_private_key.exchange(peer_public_key)

    # Use the shared secret as a key for AES-GCM encryption (AES-256 needs 32 bytes).
    aesgcm = AESGCM(shared)
    iv = os.urandom(12)  # 12-byte nonce (IV) for AES-GCM.
    ciphertext = aesgcm.encrypt(iv, envs_json, None)

    # Serialize the ephemeral public key to raw bytes.
    ephemeral_public_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Combine ephemeral public key, IV, and ciphertext.
    result = ephemeral_public_bytes + iv + ciphertext

    # Return the result as a hexadecimal string.
    return result.hex()


def parse_port_mapping(port_str: str) -> Dict:
    """Parse a port mapping string into a dictionary"""
    parts = port_str.split(':')
    if len(parts) == 3:
        return {
            "protocol": parts[0],
            "host_address": "127.0.0.1",
            "host_port": int(parts[1]),
            "vm_port": int(parts[2])
        }
    elif len(parts) == 4:
        return {
            "protocol": parts[0],
            "host_address": parts[1],
            "host_port": int(parts[2]),
            "vm_port": int(parts[3])
        }
    else:
        raise argparse.ArgumentTypeError(
            f"Invalid port mapping format: {port_str}")


class UnixSocketHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that connects to a Unix domain socket."""

    def __init__(self, socket_path, timeout=None):
        super().__init__('localhost', timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout:
            sock.settimeout(self.timeout)
        print(f"Connecting to socket at: {self.socket_path}")
        sock.connect(self.socket_path)
        self.sock = sock


class VmmClient:
    """A unified HTTP client that supports both regular HTTP and Unix Domain Sockets."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.use_uds = self.base_url.startswith('unix:')

        if self.use_uds:
            self.uds_path = self.base_url[5:]  # Remove 'unix:' prefix
        else:
            # Parse the base URL for regular HTTP connections
            self.parsed_url = urllib.parse.urlparse(self.base_url)
            self.host = self.parsed_url.netloc
            self.is_https = self.parsed_url.scheme == 'https'

    def request(self, method: str, path: str, headers: Dict[str, str] = None,
                body: Any = None, stream: bool = False) -> Tuple[int, Union[Dict, str, BinaryIO]]:
        """
        Make an HTTP request to the server.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: URL path
            headers: HTTP headers
            body: Request body (will be JSON serialized if a dict)
            stream: If True, return a file-like object for reading the response

        Returns:
            Tuple of (status_code, response_data)
        """
        if headers is None:
            headers = {}

        # Prepare the body
        if isinstance(body, dict):
            body = json.dumps(body).encode('utf-8')
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'

        # Create the appropriate connection
        if self.use_uds:
            conn = UnixSocketHTTPConnection(self.uds_path)
        else:
            if self.is_https:
                # TODO: we should verify TLS cert.
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(self.host, context=context)
            else:
                conn = http.client.HTTPConnection(self.host)

        try:
            # Make the request
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()

            status = response.status

            # Handle the response based on the stream parameter
            if stream:
                return status, response
            else:
                data = response.read()

                # Try to parse as JSON if it looks like JSON
                content_type = response.getheader('Content-Type', '')
                if 'application/json' in content_type or data.startswith(b'{') or data.startswith(b'['):
                    try:
                        return status, json.loads(data.decode('utf-8'))
                    except json.JSONDecodeError:
                        pass

                # Return as string if not JSON
                return status, data.decode('utf-8')
        except Exception as e:
            if not stream:
                conn.close()
            raise e

        # Note: when stream=True, the caller must close the connection when done


class VmmCLI:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.headers = {
            'Content-Type': 'application/json'
        }
        self.client = VmmClient(base_url)

    def rpc_call(self, method: str, params: Optional[Dict] = None) -> Dict:
        """Make an RPC call to the dstack-vmm API"""
        path = f"/prpc/{method}?json"
        status, response = self.client.request(
            'POST', path, headers=self.headers, body=params or {})

        if status != 200:
            if isinstance(response, str):
                error_msg = response
            else:
                error_msg = str(response)
            raise Exception(f"API call failed: {error_msg}")

        return response

    def list_vms(self, verbose: bool = False) -> None:
        """List all VMs and their status"""
        response = self.rpc_call('Status')
        vms = response['vms']

        if not vms:
            print("No VMs found")
            return

        headers = ['VM ID', 'App ID', 'Name', 'Status', 'Uptime']
        if verbose:
            headers.extend(['vCPU', 'Memory', 'Disk', 'Image'])

        rows = []
        for vm in vms:
            row = [
                vm['id'],
                vm['app_id'],
                vm['name'],
                vm['status'],
                vm.get('uptime', '-')
            ]

            if verbose:
                config = vm.get('configuration', {})
                row.extend([
                    config.get('vcpu', '-'),
                    f"{config.get('memory', '-')}MB",
                    f"{config.get('disk_size', '-')}GB",
                    config.get('image', '-')
                ])

            rows.append(row)

        print(format_table(rows, headers))

    def start_vm(self, vm_id: str) -> None:
        """Start a VM"""
        self.rpc_call('StartVm', {'id': vm_id})
        print(f"Started VM {vm_id}")

    def stop_vm(self, vm_id: str, force: bool = False) -> None:
        """Stop a VM"""
        if force:
            self.rpc_call('StopVm', {'id': vm_id})
            print(f"Forcefully stopped VM {vm_id}")
        else:
            self.rpc_call('ShutdownVm', {'id': vm_id})
            print(f"Gracefully shutting down VM {vm_id}")

    def remove_vm(self, vm_id: str) -> None:
        """Remove a VM"""
        self.rpc_call('RemoveVm', {'id': vm_id})
        print(f"Removed VM {vm_id}")

    def show_logs(self, vm_id: str, lines: int = 20, follow: bool = False) -> None:
        """Show VM logs"""
        path = f"/logs?id={vm_id}&follow={str(follow).lower()}&ansi=false&lines={lines}"

        status, response = self.client.request(
            'GET', path, headers=self.headers, stream=follow)

        if status != 200:
            if isinstance(response, str):
                error_msg = response
            else:
                error_msg = str(response)
            print(f"Failed to get logs: {error_msg}")
            return

        if follow:
            try:
                # For streamed responses, response is a file-like object
                while True:
                    line = response.readline()
                    if not line:
                        break
                    print(line.decode('utf-8').rstrip())
            except KeyboardInterrupt:
                # Allow clean exit with Ctrl+C
                return
            finally:
                # Close the connection when done
                response.close()
        else:
            # For non-streamed responses, response is already the data
            print(response)

    def list_images(self) -> List[Dict]:
        """Get list of available images"""
        response = self.rpc_call('ListImages')
        return response['images']

    def get_app_env_encrypt_pub_key(self, app_id: str, kms_url: Optional[str] = None) -> Dict:
        """Get the encryption public key for the specified application ID"""
        if kms_url:
            client = VmmClient(kms_url)
            path = f"/prpc/GetAppEnvEncryptPubKey?json"
            status, response = client.request(
                'POST', path, headers={
                'Content-Type': 'application/json'
            }, body={'app_id': app_id})
            print(f"Getting encryption public key for {app_id} from {kms_url}")
        else:
            response = self.rpc_call('GetAppEnvEncryptPubKey', {'app_id': app_id})

        # Verify the signature if available
        if 'signature' not in response:
            if not self.confirm_untrusted_signer("none"):
                raise Exception("Aborted due to invalid signature")
            return response['public_key']

        public_key = bytes.fromhex(response['public_key'])
        signature = bytes.fromhex(response['signature'])

        signer_pubkey = verify_signature(public_key, signature, app_id)
        if signer_pubkey:
            whitelist = load_whitelist()
            if whitelist and signer_pubkey not in whitelist:
                print(
                    f"WARNING: Signer {signer_pubkey} is not in the trusted whitelist!")
                if not self.confirm_untrusted_signer(signer_pubkey):
                    raise Exception("Aborted due to untrusted signer")
            else:
                print(f"Verified signature from: {signer_pubkey}")
        else:
            print("WARNING: Could not verify signature!")
            if not self.confirm_untrusted_signer("unknown"):
                raise Exception("Aborted due to invalid signature")

        return response['public_key']

    def confirm_untrusted_signer(self, signer: str) -> bool:
        """Ask user to confirm using an untrusted signer"""
        response = input(f"Continue with untrusted signer {signer}? (y/N): ")
        return response.lower() in ('y', 'yes')

    def manage_kms_whitelist(self, action: str, pubkey: str = None) -> None:
        """Manage the whitelist of trusted signers"""
        whitelist = load_whitelist()

        if action == 'list':
            if not whitelist:
                print("Whitelist is empty")
            else:
                print("Trusted signers:")
                for addr in whitelist:
                    print(f"  {addr}")
            return

        # Normalize pubkey format - trim 0x prefix if present
        if pubkey and pubkey.startswith('0x'):
            pubkey = pubkey[2:]
        # Convert to bytes for validation
        try:
            pubkey = bytes.fromhex(pubkey)
        except ValueError:
            raise Exception(f"Invalid public key format: {pubkey}")
        if len(pubkey) != 33:
            raise Exception(f"Invalid public key length: {len(pubkey)}")
        pubkey = pubkey.hex()

        if action == 'add':
            if pubkey in whitelist:
                print(f"Public key {pubkey} is already in the whitelist")
            else:
                whitelist.append(pubkey)
                save_whitelist(whitelist)
                print(f"Added {pubkey} to the whitelist")

        elif action == 'remove':
            if pubkey not in whitelist:
                print(f"Public key {pubkey} is not in the whitelist")
            else:
                whitelist.remove(pubkey)
                save_whitelist(whitelist)
                print(f"Removed {pubkey} from the whitelist")

        else:
            raise Exception(f"Unknown action: {action}")

    def calc_app_id(self, compose_file: str) -> str:
        """Calculate the application ID from the compose file"""
        compose_hash = hashlib.sha256(compose_file.encode()).hexdigest()
        return compose_hash[:40]

    def create_app_compose(self,
                           name: str,
                           prelaunch_script: str,
                           docker_compose: str,
                           kms_enabled: bool,
                           gateway_enabled: bool,
                           local_key_provider_enabled: bool,
                           key_provider_id: str,
                           public_logs: bool,
                           public_sysinfo: bool,
                           envs: Optional[Dict],
                           no_instance_id: bool,
                           output: str,
                           ) -> None:
        """Create a new app compose file"""
        app_compose = {
            "manifest_version": 2,
            "name": name,
            "runner": "docker-compose",
            "docker_compose_file": open(docker_compose, 'rb').read().decode('utf-8'),
            "kms_enabled": kms_enabled,
            "gateway_enabled": gateway_enabled,
            "local_key_provider_enabled": local_key_provider_enabled,
            "key_provider_id": key_provider_id,
            "public_logs": public_logs,
            "public_sysinfo": public_sysinfo,
            "allowed_envs": [k for k in envs.keys()],
            "no_instance_id": no_instance_id,
            "secure_time": True,
        }
        if prelaunch_script:
            app_compose["pre_launch_script"] = open(prelaunch_script, 'rb').read().decode('utf-8')

        compose_file = json.dumps(app_compose, indent=4, ensure_ascii=False).encode('utf-8')
        compose_hash = hashlib.sha256(compose_file).hexdigest()
        with open(output, 'wb') as f:
            f.write(compose_file)
        print(f"App compose file created at: {output}")
        print(f"Compose hash: {compose_hash}")

    def create_vm(self, name: str, image: str, compose_file: str,
                  vcpu: int = 1, memory: int = 1024, disk_size: int = 20,
                  envs: Optional[Dict] = None,
                  app_id: Optional[str] = None,
                  ports: Optional[List[str]] = None,
                  gpus: Optional[List[str]] = None,
                  pin_numa: bool = False,
                  hugepages: bool = False,
                  kms_urls: Optional[List[str]] = None,
                  gateway_urls: Optional[List[str]] = None,
                  ) -> None:
        """Create a new VM"""
        # Read and validate compose file
        if not os.path.exists(compose_file):
            raise Exception(f"Compose file not found: {compose_file}")

        with open(compose_file, 'r') as f:
            compose_content = f.read()

        # Create VM request
        params = {
            "name": name,
            "image": image,
            "compose_file": compose_content,
            "vcpu": vcpu,
            "memory": memory,
            "disk_size": disk_size,
            "app_id": app_id,
            "ports": [parse_port_mapping(port) for port in ports or []],
            "hugepages": hugepages,
            "pin_numa": pin_numa,
        }

        if gpus:
            params["gpus"] = {
                "attach_mode": "listed",
                "gpus": [{"slot": gpu} for gpu in gpus or []]
            }
        if kms_urls:
            params["kms_urls"] = kms_urls
        if gateway_urls:
            params["gateway_urls"] = gateway_urls

        app_id = app_id or self.calc_app_id(compose_content)
        print(f"App ID: {app_id}")
        if envs:
            encrypt_pubkey = self.get_app_env_encrypt_pub_key(app_id, kms_urls[0] if kms_urls else None)
            print(
                f"Encrypting environment variables with key: {encrypt_pubkey}")
            envs_list = [{"key": k, "value": v} for k, v in envs.items()]
            params["encrypted_env"] = encrypt_env(envs_list, encrypt_pubkey)
        response = self.rpc_call('CreateVm', params)
        print(f"Created VM with ID: {response.get('id')}")
        return response.get('id')

    def update_vm_env(self, vm_id: str, envs: Dict[str, str], kms_urls: Optional[List[str]] = None) -> None:
        """Update environment variables for a VM"""
        # First get the VM info to retrieve the app_id
        vm_info_response = self.rpc_call('GetInfo', {'id': vm_id})

        if not vm_info_response.get('found', False) or 'info' not in vm_info_response:
            raise Exception(f"VM with ID {vm_id} not found")

        app_id = vm_info_response['info']['app_id']
        print(f"Retrieved app ID: {app_id}")

        # Now get the encryption key for the app
        encrypt_pubkey = self.get_app_env_encrypt_pub_key(app_id, kms_urls[0] if kms_urls else None)
        print(f"Encrypting environment variables with key: {encrypt_pubkey}")
        envs_list = [{"key": k, "value": v} for k, v in envs.items()]
        encrypted_env = encrypt_env(envs_list, encrypt_pubkey)

        # Use UpdateApp with the VM ID
        self.rpc_call('UpgradeApp', {'id': vm_id,
                      'encrypted_env': encrypted_env})
        print(f"Environment variables updated for VM {vm_id}")

    def update_vm_user_config(self, vm_id: str, user_config: str) -> None:
        """Update user config for a VM"""
        self.rpc_call('UpgradeApp', {'id': vm_id,
                      'user_config': user_config})
        print(f"User config updated for VM {vm_id}")

    def update_vm_app_compose(self, vm_id: str, app_compose: str) -> None:
        """Update app compose for a VM"""
        self.rpc_call('UpgradeApp', {'id': vm_id,
                      'compose_file': app_compose})
        print(f"App compose updated for VM {vm_id}")

    def list_gpus(self) -> None:
        """List all available GPUs"""
        response = self.rpc_call('ListGpus')
        gpus = response.get('gpus', [])

        if not gpus:
            print("No GPUs found")
            return

        headers = ['Slot', 'Product ID', 'Description', 'Available']
        rows = []
        for gpu in gpus:
            row = [
                gpu.get('slot', '-'),
                gpu.get('product_id', '-'),
                gpu.get('description', '-'),
                'Yes' if gpu.get('is_free', False) else 'No'
            ]
            rows.append(row)

        print(format_table(rows, headers))


def format_table(rows, headers):
    """Simple table formatter"""
    if not rows:
        return ""

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    # Create format string
    row_format = "│ " + " │ ".join(f"{{:<{w}}}" for w in widths) + " │"
    separator = "├─" + "─┼─".join("─" * w for w in widths) + "─┤"
    top_border = "┌─" + "─┬─".join("─" * w for w in widths) + "─┐"
    bottom_border = "└─" + "─┴─".join("─" * w for w in widths) + "─┘"

    # Build table
    table = [
        top_border,
        row_format.format(*headers),
        separator
    ]
    for row in rows:
        table.append(row_format.format(*[str(cell) for cell in row]))
    table.append(bottom_border)

    return "\n".join(table)


def parse_env_file(file_path: str) -> Dict[str, str]:
    """
    Parse an environment file where each line is formatted as:
      KEY=Value

    Lines that are empty or start with '#' are ignored.
    """
    if not file_path:
        return {}

    envs = {}
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            envs[key.strip()] = value.strip()
    return envs


def parse_size(s: str, target_unit: str) -> int:
    """
    Parse a human-readable size string (e.g. "1G", "100M") and return the size
    in the specified target unit.

    Args:
        s: The size string provided.
        target_unit: Either "MB" (for memory) or "GB" (for disk).

    Returns:
        An integer representing the size in the specified unit.

    Raises:
        argparse.ArgumentTypeError: if the format is invalid or if conversion turns
                                      out to be fractional.
    """
    s = s.strip()
    m = re.fullmatch(r'(\d+(?:\.\d+)?)([a-zA-Z]{1,2})?', s)
    if not m:
        raise argparse.ArgumentTypeError(f"Invalid size format: '{s}'")
    number_str, unit = m.groups()
    try:
        number = float(number_str)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid number in size: '{s}'")

    # If no unit is specified, assume the target unit.
    if unit is None:
        unit = target_unit
    else:
        unit = unit.upper()

    if target_unit == "MB":
        # For memory, if no suffix is provided we assume MB.
        if unit in ["M", "MB"]:
            factor = 1
        elif unit in ["G", "GB"]:
            factor = 1024
        elif unit in ["T", "TB"]:
            factor = 1024 * 1024
        else:
            raise argparse.ArgumentTypeError(
                f"Invalid size unit '{unit}' for memory. Use M, G, or T.")
    elif target_unit == "GB":
        # For disk, if no suffix is provided we assume GB.
        if unit in ["G", "GB"]:
            factor = 1
        elif unit in ["T", "TB"]:
            factor = 1024
        else:
            raise argparse.ArgumentTypeError(
                f"Invalid size unit '{unit}' for disk. Use G, T.")
    else:
        raise ValueError("Unsupported target unit")

    value = number * factor
    if not value.is_integer():
        raise argparse.ArgumentTypeError(
            f"Size must be an integer number of {target_unit}. Got {value}.")
    return int(value)


def parse_memory_size(s: str) -> int:
    """Parse a memory size string into MB."""
    return parse_size(s, "MB")


def parse_disk_size(s: str) -> int:
    """Parse a disk size string into GB."""
    return parse_size(s, "GB")


def verify_signature(public_key: bytes, signature: bytes, app_id: str) -> Optional[str]:
    """
    Verify the signature of a public key.

    Args:
        public_key: The public key bytes to verify
        signature: The signature bytes
        app_id: The application ID

    Returns:
        The compressed public key if valid, None otherwise

    Examples:
        >>> public_key = bytes.fromhex('e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a')
        >>> signature = bytes.fromhex('8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00')
        >>> app_id = '00' * 20
        >>> compressed_pubkey = verify_signature(public_key, signature, app_id)
        >>> print(compressed_pubkey)
        0x0217610d74cbd39b6143842c6d8bc310d79da1d82cc9d17f8876376221eda0c38f
    """
    if len(signature) != 65:
        return None

    # Create the message to verify
    prefix = b"dstack-env-encrypt-pubkey"
    if app_id.startswith("0x"):
        app_id = app_id[2:]
    message = prefix + b":" + bytes.fromhex(app_id) + public_key

    # Hash the message with Keccak-256
    message_hash = keccak(message)

    # Recover the public key from the signature
    try:
        # Create a Signature object with vrs
        sig = keys.Signature(signature_bytes=signature)

        recovered_key = sig.recover_public_key_from_msg_hash(message_hash)
        return '0x' + recovered_key.to_compressed_bytes().hex()
    except Exception as e:
        print(f"Signature verification failed: {e}", file=sys.stderr)
        return None


def load_whitelist() -> List[str]:
    """
    Load the whitelist of trusted signers from a file.

    Returns:
        List of trusted Ethereum addresses
    """
    if not os.path.exists(DEFAULT_KMS_WHITELIST_PATH):
        os.makedirs(os.path.dirname(DEFAULT_KMS_WHITELIST_PATH), exist_ok=True)
        return []

    try:
        with open(DEFAULT_KMS_WHITELIST_PATH, 'r') as f:
            data = json.load(f)
            return data.get('trusted_signers', [])
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def save_whitelist(whitelist: List[str]) -> None:
    """
    Save the whitelist of trusted signers to a file.

    Args:
        whitelist: List of trusted Ethereum addresses
    """
    os.makedirs(os.path.dirname(DEFAULT_KMS_WHITELIST_PATH), exist_ok=True)
    with open(DEFAULT_KMS_WHITELIST_PATH, 'w') as f:
        json.dump({'trusted_signers': whitelist}, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description='dstack-vmm CLI - Manage VMs')
    parser.add_argument(
        '--url', default='http://localhost:10330', help='dstack-vmm API URL')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # List command
    lsvm_parser = subparsers.add_parser('lsvm', help='List VMs')
    lsvm_parser.add_argument(
        '-v', '--verbose', action='store_true', help='Show detailed information')

    # Start command
    start_parser = subparsers.add_parser('start', help='Start a VM')
    start_parser.add_argument('vm_id', help='VM ID to start')

    # Stop command
    stop_parser = subparsers.add_parser('stop', help='Stop a VM')
    stop_parser.add_argument('vm_id', help='VM ID to stop')
    stop_parser.add_argument(
        '-f', '--force', action='store_true', help='Force stop the VM')

    # Remove command
    remove_parser = subparsers.add_parser('remove', help='Remove a VM')
    remove_parser.add_argument('vm_id', help='VM ID to remove')

    # Logs command
    logs_parser = subparsers.add_parser('logs', help='Show VM logs')
    logs_parser.add_argument('vm_id', help='VM ID to show logs for')
    logs_parser.add_argument('-n', '--lines', type=int,
                             default=20, help='Number of lines to show')
    logs_parser.add_argument(
        '-f', '--follow', action='store_true', help='Follow log output')

    # Compose command
    compose_parser = subparsers.add_parser(
        'compose', help='Create a new app-compose.json file')
    compose_parser.add_argument('--name', required=True, help='VM image name')
    compose_parser.add_argument(
        '--docker-compose', required=True, help='Path to docker-compose.yml file')
    compose_parser.add_argument(
        '--prelaunch-script', default=None, help='Path to prelaunch script')
    compose_parser.add_argument(
        '--kms', action='store_true', help='Enable KMS')
    compose_parser.add_argument(
        '--gateway', action='store_true', help='Enable dstack-gateway')
    compose_parser.add_argument(
        '--local-key-provider', action='store_true', help='Enable local key provider')
    compose_parser.add_argument(
        '--key-provider-id', default="", help='Key provider ID if you want to bind to a specific key provider')
    compose_parser.add_argument(
        '--public-logs', action='store_true', help='Enable public logs')
    compose_parser.add_argument(
        '--public-sysinfo', action='store_true', help='Enable public sysinfo')
    compose_parser.add_argument(
        '--env-file', help='File with environment variables to encrypt', default=None)
    compose_parser.add_argument(
        '--no-instance-id', action='store_true', help='Disable instance ID')
    compose_parser.add_argument(
        '--output', required=True, help='Path to output app-compose.json file')

    # Deploy command
    deploy_parser = subparsers.add_parser('deploy', help='Deploy a new VM')
    deploy_parser.add_argument('--name', required=True, help='VM name')
    deploy_parser.add_argument('--image', required=True, help='VM image')
    deploy_parser.add_argument(
        '--compose', required=True, help='Path to app-compose.json file')
    deploy_parser.add_argument(
        '--vcpu', type=int, default=1, help='Number of vCPUs')
    deploy_parser.add_argument(
        '--memory', type=parse_memory_size, default=1024, help='Memory size (e.g. 1G, 100M)')
    deploy_parser.add_argument(
        '--disk', type=parse_disk_size, default=20, help='Disk size (e.g. 1G, 100M)')
    deploy_parser.add_argument(
        '--env-file', help='File with environment variables to encrypt', default=None)
    deploy_parser.add_argument('--app-id', help='Application ID', default=None)
    deploy_parser.add_argument('--port', action='append', type=str,
                               help='Port mapping in format: protocol[:address]:from:to')
    deploy_parser.add_argument('--gpu', action='append', type=str,
                               help='GPU in product_id')
    deploy_parser.add_argument('--pin-numa', action='store_true',
                               help='Pin VM to specific NUMA node')
    deploy_parser.add_argument('--hugepages', action='store_true',
                               help='Enable hugepages for the VM')
    deploy_parser.add_argument('--kms-url', action='append', type=str,
                               help='KMS URL')
    deploy_parser.add_argument('--gateway-url', action='append', type=str,
                               help='Gateway URL')

    # Images command
    _images_parser = subparsers.add_parser(
        'lsimage', help='List available images')

    # GPU command
    _lsgpu_parser = subparsers.add_parser('lsgpu', help='List available GPUs')

    # Update environment variables command
    update_env_parser = subparsers.add_parser(
        'update-env', help='Update environment variables for a VM')
    update_env_parser.add_argument('vm_id', help='VM ID to update')
    update_env_parser.add_argument(
        '--env-file', required=True, help='File with environment variables to encrypt')
    update_env_parser.add_argument(
        '--kms-url', action='append', type=str,
        help='KMS URL')

    # Whitelist command
    kms_parser = subparsers.add_parser(
        'kms', help='Manage trusted KMS whitelist')
    kms_subparsers = kms_parser.add_subparsers(
        dest='kms_action', help='KMS actions')

    # List whitelist
    list_kms_parser = kms_subparsers.add_parser(
        'list', help='List trusted signers')

    # Add to whitelist
    add_kms_parser = kms_subparsers.add_parser(
        'add', help='Add public key to trusted signers')
    add_kms_parser.add_argument('pubkey', help='Public key to add')

    # Remove from whitelist
    remove_kms_parser = kms_subparsers.add_parser(
        'remove', help='Remove public key from trusted signers')
    remove_kms_parser.add_argument('pubkey', help='Public key to remove')

    # Update app compose
    update_app_compose_parser = subparsers.add_parser(
        'update-app-compose', help='Update app compose for a VM')
    update_app_compose_parser.add_argument('vm_id', help='VM ID to update')
    update_app_compose_parser.add_argument(
        'compose', help='Path to app-compose.json file')

    # Update user config
    update_user_config_parser = subparsers.add_parser(
        'update-user-config', help='Update user config for a VM')
    update_user_config_parser.add_argument('vm_id', help='VM ID to update')
    update_user_config_parser.add_argument(
        'user_config', help='Path to user config file')

    args = parser.parse_args()

    cli = VmmCLI(args.url)

    if args.command == 'lsvm':
        cli.list_vms(args.verbose)
    elif args.command == 'start':
        cli.start_vm(args.vm_id)
    elif args.command == 'stop':
        cli.stop_vm(args.vm_id, args.force)
    elif args.command == 'remove':
        cli.remove_vm(args.vm_id)
    elif args.command == 'logs':
        cli.show_logs(args.vm_id, args.lines, args.follow)
    elif args.command == 'compose':
        cli.create_app_compose(
            name=args.name,
            prelaunch_script=args.prelaunch_script,
            docker_compose=args.docker_compose,
            kms_enabled=args.kms,
            gateway_enabled=args.gateway,
            local_key_provider_enabled=args.local_key_provider,
            key_provider_id=args.key_provider_id,
            public_logs=args.public_logs,
            public_sysinfo=args.public_sysinfo,
            envs=parse_env_file(args.env_file),
            no_instance_id=args.no_instance_id,
            output=args.output
        )
    elif args.command == 'deploy':
        cli.create_vm(
            name=args.name,
            image=args.image,
            compose_file=args.compose,
            vcpu=args.vcpu,
            memory=args.memory,
            disk_size=args.disk,
            ports=args.port,
            envs=parse_env_file(args.env_file),
            app_id=args.app_id,
            gpus=args.gpu,
            hugepages=args.hugepages,
            pin_numa=args.pin_numa,
            kms_urls=args.kms_url,
            gateway_urls=args.gateway_url
        )
    elif args.command == 'lsimage':
        images = cli.list_images()
        headers = ['Name', 'Version']
        rows = [[img['name'], img.get('version', '-')] for img in images]
        print(format_table(rows, headers))
    elif args.command == 'lsgpu':
        cli.list_gpus()
    elif args.command == 'update-env':
        cli.update_vm_env(args.vm_id, parse_env_file(args.env_file), kms_urls=args.kms_url)
    elif args.command == 'update-user-config':
        cli.update_vm_user_config(args.vm_id, open(args.user_config, 'r').read())
    elif args.command == 'update-app-compose':
        cli.update_vm_app_compose(args.vm_id, open(args.compose, 'r').read())
    elif args.command == 'kms':
        if not args.kms_action:
            kms_parser.print_help()
        else:
            cli.manage_kms_whitelist(
                action=args.kms_action,
                pubkey=getattr(args, 'pubkey', None),
            )
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
