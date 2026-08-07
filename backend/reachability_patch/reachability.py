import ast
import os
from typing import List
from backend.schemas import VulnerabilityItem, ReachabilityResult

# Common PyPI package name -> Import module name mappings
PACKAGE_TO_MODULE = {
    "pyyaml": ["yaml"],
    "scikit-learn": ["sklearn"],
    "opencv-python": ["cv2"],
    "pillow": ["PIL"],
    "python-dateutil": ["dateutil"],
    "beautifulsoup4": ["bs4"],
    "protobuf": ["google.protobuf"]
}

class DependencyVisitor(ast.NodeVisitor):
    def __init__(self, target_pkg: str):
        pkg_lower = target_pkg.lower()
        # Get target module names (e.g., 'pyyaml' maps to ['yaml', 'pyyaml'])
        self.target_modules = PACKAGE_TO_MODULE.get(pkg_lower, [pkg_lower])
        if pkg_lower not in self.target_modules:
            self.target_modules.append(pkg_lower)
            
        self.found_import = False
        self.imported_names: List[str] = []

    def _matches_target(self, name: str) -> bool:
        name_lower = name.lower()
        return any(mod in name_lower for mod in self.target_modules)

    def visit_Import(self, node):
        for alias in node.names:
            if self._matches_target(alias.name):
                self.found_import = True
                self.imported_names.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module and self._matches_target(node.module):
            self.found_import = True
            self.imported_names.append(node.module)
        self.generic_visit(node)

def check_reachability(repo_path: str, vuln: VulnerabilityItem) -> ReachabilityResult:
    matched_files = []
    detected_imports = []
    evidence = ""

    for root, dirs, files in os.walk(repo_path):
        # Ignore virtual environment folders
        if "venv" in root or ".venv" in root or "__pycache__" in root:
            continue

        for file in files:
            if file.endswith(".py") and not file.startswith("test_local"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        code = f.read()
                    
                    tree = ast.parse(code, filename=file)
                    visitor = DependencyVisitor(vuln.package_name)
                    visitor.visit(tree)

                    if visitor.found_import:
                        matched_files.append(file_path)
                        detected_imports.extend(visitor.imported_names)
                        evidence = "\n".join(code.splitlines()[:5])
                except Exception:
                    continue

    is_reachable = len(matched_files) > 0

    return ReachabilityResult(
        vulnerability=vuln,
        is_reachable=is_reachable,
        detected_imports=list(set(detected_imports)),
        matched_files=matched_files,
        evidence_snippet=evidence if is_reachable else None
    )