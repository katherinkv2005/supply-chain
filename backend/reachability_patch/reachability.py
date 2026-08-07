import ast
import os
from typing import List
from backend.schemas import VulnerabilityItem, ReachabilityResult

class DependencyVisitor(ast.NodeVisitor):
    def __init__(self, target_pkg: str):
        self.target_pkg = target_pkg.lower()
        self.found_import = False
        self.imported_names: List[str] = []

    def visit_Import(self, node):
        for alias in node.names:
            if self.target_pkg in alias.name.lower():
                self.found_import = True
                self.imported_names.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module and self.target_pkg in node.module.lower():
            self.found_import = True
            self.imported_names.append(node.module)
        self.generic_visit(node)

def check_reachability(repo_path: str, vuln: VulnerabilityItem) -> ReachabilityResult:
    matched_files = []
    detected_imports = []
    evidence = ""

    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith(".py"):
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