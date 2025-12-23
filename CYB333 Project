import os
import subprocess
from typing import Dict, Any, List


#CIS benchmarks for security checks
cis_benchmarks = [
    {
        "id": "CIS-1.1",
        "description": "Ensure SSH root login is disabled",
        "check_type": "ssh_root_login",
        "expected": "no"
    },
    {
        "id": "CIS-1.2",
        "description": "Enforce password complexity",
        "check_type": "password_policy",
        "expected": True
    },
    {
        "id": "CIS-1.3",
        "description": "Ensure /etc/passwd permissions are configured",
        "check_type": "file_permissions",
        "path": "/etc/passwd",
        "expected": "644"
    },
    {
        "id": "CIS-1.4",
        "description": "Ensure macOS Application Firewall is enabled",
        "check_type": "mac_firewall_enabled",
        "expected": True,
        "recommendation": "Enable firewall in System Settings > Network > Firewall (or use socketfilterfw with sudo)."
    },
    {
        "id": "CIS-1.5",
        "description": "Ensure FileVault is enabled",
        "check_type": "filevault_enabled",
        "expected": True,
        "recommendation": "Enable FileVault in System Settings > Privacy & Security > FileVault."
    },
]
audit_results = []

def run_cmd(cmd: List[str]) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return {"rc": p.returncode, "stdout": (p.stdout or "").strip(), "stderr": (p.stderr or "").strip()}
    except Exception as e:
        return {"rc": 999, "stdout": "", "stderr": f"{type(e).__name__}: {e}"}

def check_ssh_root_login(expected: str = "no") -> bool:
    sshd_config_path = "/etc/ssh/sshd_config"
    if not os.path.exists(sshd_config_path):
        return {
            "status": "ERROR",
            "passed": False,
            "evidence": "",
            "error": f"{sshd_config_path} not found (SSH may not be enabled on macOS by default)."
        }
    try:
        with open(sshd_config_path, "r", encoding="utf-8", errors="ignore") as f:
                  lines = f.readlines()
                  
        value = None
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.lower().startswith("permitrootlogin"):
                parts = stripped.split()
                if len(parts) >= 2:
                    value = parts[1].lower()

        if value is None:
            return {"status": "FAIL", "passed": False, "evidence": "PermitRootLogin not explicitly set", "error": ""}

        passed = (value == expected.lower())
        return {"status": "PASS" if passed else "FAIL", "passed": passed, "evidence": f"PermitRootLogin {value}", "error": ""}

    except Exception as e:
        return {"status": "ERROR", "passed": False, "evidence": "", "error": f"{type(e).__name__}: {e}"}

def check_password_policy(expected: bool = True) -> Dict[str, Any]:
    result = run_cmd(["pwpolicy", "getaccountpolicies"])
    if result["rc"] != 0:
        return {
            "status": "ERROR",
            "passed": False,
            "evidence": "",
            "error": f"pwpolicy failed (rc={result['rc']}): {result['stderr'] or 'unknown error'}"
        }

    output = result["stdout"].lower()

    indicators = ["minlength", "requiresalpha", "requiresnumeric"]
    found = [i for i in indicators if i in output]
    passed = (len(found) == len(indicators)) if expected else True

    return {
        "status": "PASS" if passed else "FAIL",
        "passed": passed,
        "evidence": f"Indicators found: {found}",
        "error": ""
    }

def run_check(benchmark: dict) -> bool:
    check_type = benchmark.get("check_type")
    expected = benchmark.get("expected")
    if check_type == "ssh_root_login":
        return check_ssh_root_login(expected)
    elif check_type == "password_policy":
        return check_password_policy(expected)
    elif check_type == "mac_firewall_enabled":
        return check_mac_firewall_enabled(expected)
    elif check_type == "filevault_enabled":
        return check_filevault_enabled(expected)
    elif check_type == "file_permissions":
        path = benchmark.get("path")
        if not path:
            return False
        return check_file_permissions(path, expected)
    else:
        return False
    
def audit_system(benchmarks):
    results = []
    for benchmark in benchmarks:
        passed = run_check(benchmark)
        results.append({
            "id": benchmark["id"],
            "description": benchmark["description"],
            "passed": passed
        })
    return results

def print_report(audit_results):
    passed_count = sum(1 for r in audit_results if r["passed"])
    total = len(audit_results)
    compliance_percentage = (passed_count / total) * 100 if total else 0.0
    print("\nCIS Benchmark Audit Results\n")
    for r in audit_results:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"{r['id']} - {r['description']}: {status}")
    print(f"\nOverall Compliance: {compliance_percentage:.2f}%")
    return compliance_percentage

def check_file_permissions(path: str, expected: str) -> Dict[str, Any]:
    try:
        stat_info = os.stat(path)
        actual_permissions = oct(stat_info.st_mode)[-3:]
        passed = (actual_permissions == expected)
        return {
            "status": "PASS" if passed else "FAIL",
            "passed": passed,
            "evidence": f"{path} perms={actual_permissions}",
            "error": ""
        }
    except Exception as e:
        return {"status": "ERROR", "passed": False, "evidence": "", "error": f"{type(e).__name__}: {e}"}

def check_mac_firewall_enabled(expected: bool = True) -> Dict[str, Any]:
    cmd = ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]
    result = run_cmd(cmd)
    if result["rc"] != 0:
        return {
            "status": "ERROR",
            "passed": False,
            "evidence": "",
            "error": f"socketfilterfw failed (rc={result['rc']}): {result['stderr'] or 'unknown error'}"
        }

    out = result["stdout"].lower()
    is_enabled = ("enabled" in out) and ("disabled" not in out)
    passed = (is_enabled == expected)
    return {
        "status": "PASS" if passed else "FAIL",
        "passed": passed,
        "evidence": result["stdout"],
        "error": ""
    }
def check_filevault_enabled(expected: bool = True) -> Dict[str, Any]:
    result = run_cmd(["fdesetup", "status"])
    if result["rc"] != 0:
        return {
            "status": "ERROR",
            "passed": False,
            "evidence": "",
            "error": f"fdesetup failed (rc={result['rc']}): {result['stderr'] or 'unknown error'}"
        }

    out = result["stdout"].lower()
    is_on = "filevault is on" in out
    passed = (is_on == expected)
    return {
        "status": "PASS" if passed else "FAIL",
        "passed": passed,
        "evidence": result["stdout"],
        "error": ""
    }

if __name__ == "__main__":
    results = audit_system(cis_benchmarks)
    print_report(results)