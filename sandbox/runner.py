import os
import shutil
import tempfile
import json
import logging
from typing import Dict, Any, Optional

import docker
from docker.models.containers import Container

# Set up logging for the Sandbox
logging.basicConfig(level=logging.INFO, format="%(asctime)s - sandbox - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

SANDBOX_IMAGE = "deadsec/sandbox:latest"
DEFAULT_TIMEOUT_SEC = 30

class SandboxRunner:
    def __init__(self):
        try:
            self.client = docker.from_env()
        except Exception as e:
            logger.error(f"Cannot connect to Docker daemon: {e}")
            raise

    def build_image(self):
        """Builds the sandbox Docker image from the local Dockerfile if needed."""
        logger.info(f"Building/checking Docker image {SANDBOX_IMAGE}...")
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.client.images.build(path=base_dir, tag=SANDBOX_IMAGE, rm=True)
        logger.info("Image build complete.")

    def analyze_file(self, target_binary: str, timeout: int = DEFAULT_TIMEOUT_SEC) -> Dict[str, Any]:
        """Runs the file in an isolated container and extracts syscall/network traces."""
        if not os.path.exists(target_binary):
            raise FileNotFoundError(f"Binary {target_binary} not found.")

        # Create a temporary directory to hold the output (strace logs, stdout, pcaps)
        output_dir = tempfile.mkdtemp(prefix="sandbox_out_")
        target_name = os.path.basename(target_binary)
        
        # Sandbox execution payload configuration
        payload_dir = tempfile.mkdtemp(prefix="sandbox_payload_")
        shutil.copy2(target_binary, os.path.join(payload_dir, target_name))

        # Mount definitions
        # /sandbox_in : Read-Only directory containing the malware
        # /sandbox_out : Read-Write directory to collect logs (strace, tcpdump, etc.)
        volumes = {
            payload_dir: {'bind': '/sandbox_in', 'mode': 'ro'},
            output_dir: {'bind': '/sandbox_out', 'mode': 'rw'}
        }

        # Container strict isolation settings
        # We disable networking for now to prevent actual outbound calls, OR
        # enable it on an internal-only bridge if we want to monitor internal behavior.
        # For maximum safety initially, 'none' network is used.
        container: Optional[Container] = None
        
        try:
            cmd = f"/sbin/tracer.sh /sandbox_in/{target_name} {timeout}"
            
            logger.info(f"Starting isolated sandbox container for {target_name}...")
            container = self.client.containers.run(
                image=SANDBOX_IMAGE,
                command=["/bin/bash", "-c", cmd],
                volumes=volumes,
                network_mode="none", # Strict isolation (no internet)
                mem_limit="256m",    # Limit memory consumption
                cpu_quota=50000,     # Throttle CPU (50%)
                cap_drop=["ALL"],    # Drop root capabilities
                cap_add=["SYS_PTRACE"], # Needed for strace
                pids_limit=50,       # Prevent fork bombs
                privileged=False,
                detach=True
            )
            
            # Wait for execution to finish (or kill if it hangs beyond tracer.sh timeout)
            # The inner tracer.sh will normally exit after `timeout` seconds, but we add an outer safety
            result = container.wait(timeout=timeout + 10)
            
            logger.info(f"Sandbox completed with status code: {result.get('StatusCode')}")

        except Exception as e:
            logger.error(f"Sandbox error: {e}")
        finally:
            if container:
                container.remove(force=True)

        # Parse extracted results
        report = self._parse_results(output_dir)
        
        # Cleanup temp dirs
        shutil.rmtree(payload_dir, ignore_errors=True)
        shutil.rmtree(output_dir, ignore_errors=True)
        
        return report

    def _parse_results(self, output_dir: str) -> Dict[str, Any]:
        """Simple strace analyzer focusing on behavioral risks."""
        strace_log = os.path.join(output_dir, "strace.log")
        
        report = {
            "syscalls": {},
            "files_accessed": [],
            "network_activity": False,
            "risk_score": 0,
            "suspicious_actions": []
        }

        if not os.path.exists(strace_log):
            report["suspicious_actions"].append("No strace output, possibly evading or crashed immediately.")
            return report

        try:
            with open(strace_log, "r") as f:
                lines = f.readlines()
        except UnicodeDecodeError:
            with open(strace_log, "rb") as f:
                lines = [l.decode('utf-8', errors='ignore') for l in f]

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Very basic extraction (in production, use strace parsing libraries or regex)
            # e.g., 200 execve("/bin/sh", ...)
            if "execve" in line:
                report["syscalls"]["execve"] = report["syscalls"].get("execve", 0) + 1
            if "open" in line or "openat" in line:
                report["syscalls"]["open"] = report["syscalls"].get("open", 0) + 1
            if "socket" in line or "connect" in line:
                report["syscalls"]["network"] = report["syscalls"].get("network", 0) + 1
                report["network_activity"] = True

            # Heuristics
            if "/etc/shadow" in line or "/etc/passwd" in line:
                report["suspicious_actions"].append("Attempted to read password files.")
                report["risk_score"] += 3
            if "/dev/urandom" in line or "/dev/random" in line:
                # Often used internally, but extreme rates can imply crypto/ransomware
                pass
            if "rm -rf" in line or "unlink" in line:
                report["syscalls"]["unlink"] = report["syscalls"].get("unlink", 0) + 1

        if report["syscalls"].get("execve", 0) > 0:
            report["suspicious_actions"].append("Spawned child processes (execve).")
            report["risk_score"] += 1

        if report["network_activity"]:
            report["suspicious_actions"].append("Attempted network operations (sockets).")
            report["risk_score"] += 2
            
        return report

if __name__ == "__main__":
    # Test block
    runner = SandboxRunner()
    runner.build_image()
    
    # Create a dummy "malware" to safely test
    dummy_bin = "/tmp/test_malware.sh"
    with open(dummy_bin, "w") as f:
        f.write("#!/bin/bash\n")
        f.write("echo 'Connecting to secret server...'\n")
        f.write("cat /etc/passwd > /dev/null\n")
        f.write("sleep 2\n")
    os.chmod(dummy_bin, 0o755)

    print(json.dumps(runner.analyze_file(dummy_bin, timeout=5), indent=2))
