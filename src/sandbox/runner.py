"""Runs untrusted (LLM-generated) scripts in an ephemeral, locked-down container."""
import tempfile, time
from dataclasses import dataclass
from pathlib import Path
from ..ingestion.schema import VulnClass


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False


class SandboxRunner:
    def __init__(self, image="poc-runner:latest", browser_image="poc-runner-browser:latest",
                 network="lab_net", mem="256m", browser_mem="512m", cpus=0.5, browser_cpus=1.0,
                 timeout=30, browser_timeout=40, client=None):
        import docker
        self.client = client or docker.from_env()
        self.image = image
        self.browser_image = browser_image
        self.network, self.mem, self.browser_mem, self.cpus, self.browser_cpus = (
            network, mem, browser_mem, cpus, browser_cpus
        )
        self.timeout = timeout
        self.browser_timeout = browser_timeout

    def get_image(self, vuln_class: VulnClass | str | None = None) -> str:
        if vuln_class and (vuln_class == VulnClass.XSS or str(vuln_class).lower() in ("xss", "vulnclass.xss")):
            return self.browser_image
        return self.image

    def get_mem(self, vuln_class: VulnClass | str | None = None) -> str:
        if vuln_class and (vuln_class == VulnClass.XSS or str(vuln_class).lower() in ("xss", "vulnclass.xss")):
            return self.browser_mem
        return self.mem

    def get_cpus(self, vuln_class: VulnClass | str | None = None) -> float:
        if vuln_class and (vuln_class == VulnClass.XSS or str(vuln_class).lower() in ("xss", "vulnclass.xss")):
            return self.browser_cpus
        return self.cpus

    def get_pids_limit(self, vuln_class: VulnClass | str | None = None) -> int:
        if vuln_class and (vuln_class == VulnClass.XSS or str(vuln_class).lower() in ("xss", "vulnclass.xss")):
            return 256
        return 64

    def get_tmpfs(self, vuln_class: VulnClass | str | None = None) -> dict:
        if vuln_class and (vuln_class == VulnClass.XSS or str(vuln_class).lower() in ("xss", "vulnclass.xss")):
            return {"/tmp": "size=64m"}
        return {"/tmp": "size=16m"}

    def get_timeout(self, vuln_class: VulnClass | str | None = None) -> int:
        if vuln_class and (vuln_class == VulnClass.XSS or str(vuln_class).lower() in ("xss", "vulnclass.xss")):
            return self.browser_timeout
        return self.timeout

    def run(self, script: str, env: dict | None = None, vuln_class: VulnClass | str | None = None) -> SandboxResult:
        image = self.get_image(vuln_class)
        mem_limit = self.get_mem(vuln_class)
        cpus = self.get_cpus(vuln_class)
        pids_limit = self.get_pids_limit(vuln_class)
        tmpfs = self.get_tmpfs(vuln_class)
        timeout = self.get_timeout(vuln_class)
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "test.py").write_text(script)
            start = time.time()
            c = self.client.containers.run(
                image, ["python", "/work/test.py"], detach=True,
                network=self.network,                       # internal network => no internet egress
                read_only=True, cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                mem_limit=mem_limit, nano_cpus=int(cpus * 1e9), pids_limit=pids_limit,
                shm_size="64m",
                volumes={tmp: {"bind": "/work", "mode": "ro"}},
                tmpfs=tmpfs,
                environment=env or {},
            )
            timed_out = False
            try:
                code = c.wait(timeout=timeout)["StatusCode"]
            except Exception:
                timed_out, code = True, -1
                try: c.kill()
                except Exception: pass
            out = c.logs(stdout=True, stderr=False).decode(errors="replace")
            err = c.logs(stdout=False, stderr=True).decode(errors="replace")
            c.remove(force=True)
            return SandboxResult(code, out, err, time.time() - start, timed_out)
