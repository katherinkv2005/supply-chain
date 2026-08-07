import os
import json
from anthropic import Anthropic
from dotenv import load_dotenv
from backend.schemas import ReachabilityResult, PatchResult

load_dotenv()

SYSTEM_PROMPT = """You are an automated security patching agent.
You MUST respond with valid, raw JSON only matching this schema:
{
  "target_file": "path/to/file",
  "original_content": "old code or requirement line",
  "patched_content": "updated code or requirement line",
  "patch_diff": "diff summary",
  "explanation_markdown": "Detailed markdown explanation of the fix.",
  "requires_human_approval": true/false
}
Do not include any commentary or code block markers outside the raw JSON payload.
"""

def generate_patch(reach_result: ReachabilityResult, repo_path: str) -> PatchResult:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    vuln = reach_result.vulnerability
    req_file = os.path.join(repo_path, "requirements.txt")
    req_content = ""
    
    if os.path.exists(req_file):
        with open(req_file, "r") as f:
            req_content = f.read()

    try:
        if not api_key or "your_actual" in api_key or not api_key.startswith("sk-ant"):
            raise ValueError("Invalid or missing ANTHROPIC_API_KEY in .env file.")

        client = Anthropic(api_key=api_key)
        user_prompt = f"""
        CVE ID: {vuln.cve_id}
        Package: {vuln.package_name}
        Current Version: {vuln.current_version}
        Fixed Version: {vuln.fixed_version}
        Severity: {vuln.severity}
        Description: {vuln.description}
        Is Reachable: {reach_result.is_reachable}
        Matched Files: {reach_result.matched_files}
        Target Requirements Content:
        {req_content}
        """

        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1500,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}]
        )

        data = json.loads(response.content[0].text.strip())

    except Exception as e:
        # Fallback response for offline testing or unconfigured keys
        data = {
            "target_file": "requirements.txt",
            "original_content": f"{vuln.package_name}=={vuln.current_version}",
            "patched_content": f"{vuln.package_name}=={vuln.fixed_version}",
            "patch_diff": f"- {vuln.package_name}=={vuln.current_version}\n+ {vuln.package_name}=={vuln.fixed_version}",
            "explanation_markdown": f"Upgraded `{vuln.package_name}` to `{vuln.fixed_version}` to fix {vuln.cve_id}. (Mode: {str(e)})",
            "requires_human_approval": False
        }

    return PatchResult(
        cve_id=vuln.cve_id,
        package_name=vuln.package_name,
        is_reachable=reach_result.is_reachable,
        target_file=data["target_file"],
        original_content=data["original_content"],
        patched_content=data["patched_content"],
        patch_diff=data["patch_diff"],
        explanation_markdown=data["explanation_markdown"],
        requires_human_approval=data["requires_human_approval"]
    )