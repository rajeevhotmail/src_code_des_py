import ast
import glob
from typing import Dict, List
from pathlib import Path

class CodebaseAnalyzer:
    def __init__(self, path: str):
        self.path = path
        self.is_directory = Path(path).is_dir()
        self.analyzers = {}
        self.initialize_analyzers()

    def initialize_analyzers(self):
        if self.is_directory:
            for file in glob.glob(f"{self.path}/*.py"):
                self.analyzers[file] = SemanticCodeAnalyzer(file)
        else:
            self.analyzers[self.path] = SemanticCodeAnalyzer(self.path)

    def analyze_directory(self) -> Dict:
        file_relationships = {}
        workflow_graph = {}
        for file_path, analyzer in self.analyzers.items():
            file_relationships[file_path] = {
                'imports': analyzer.get_imports(),
                'exports': analyzer.get_exports(),
                'summary': analyzer.generate_file_summary(),
                'functions': analyzer.generate_function_summaries()
            }
            workflow_graph[file_path] = analyzer.get_dependencies()
        return {
            'relationships': file_relationships,
            'workflow': workflow_graph,
            'system_summary': self.generate_system_summary(file_relationships)
        }

    def generate_system_summary(self, relationships: Dict) -> str:
        entry_files = [f for f, r in relationships.items() if not r['imports']]
        utility_files = [f for f, r in relationships.items() if len(r['exports']) > len(r['imports'])]
        core_files = [f for f in relationships if f not in entry_files + utility_files]

        return f"""
        System Workflow:
        1. Entry Points: {', '.join(entry_files)}
        2. Core Processing: {', '.join(core_files)}
        3. Utility Modules: {', '.join(utility_files)}
        4. Data Flow: Files are interconnected through imports and function calls
        """

class SemanticCodeAnalyzer:
    def __init__(self, file_path: str):
        self.file_path = file_path
        with open(file_path, 'r', encoding='utf-8') as file:
            self.code = file.read()
        self.tree = ast.parse(self.code)

    def get_imports(self) -> List[str]:
        imports = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                imports.extend(n.name for n in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(f"{node.module}.{node.names[0].name}")
        return imports

    def get_exports(self) -> List[str]:
        exports = []
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                if not node.name.startswith('_'):
                    exports.append(node.name)
        return exports

    def get_dependencies(self) -> List[str]:
        deps = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    deps.append(node.func.id)
        return deps

    def generate_file_summary(self) -> str:
        return f"""
        File: {Path(self.file_path).name}
        Purpose: {self._detect_file_purpose()}
        Components: {', '.join(self.get_exports())}
        Dependencies: {', '.join(self.get_imports())}
        """

    def generate_function_summaries(self) -> Dict[str, str]:
        summaries = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                summary = {
                    'purpose': self._analyze_function_purpose(node),
                    'args': [arg.arg for arg in node.args.args],
                    'complexity': self._calculate_complexity(node),
                    'calls': self._get_function_calls(node)
                }
                summaries[node.name] = summary
        return summaries

    def _analyze_function_purpose(self, node: ast.FunctionDef) -> str:
        operations = []

        for child in ast.walk(node):
        # API Operations
            if isinstance(child, ast.Call):
                if hasattr(child.func, 'attr'):
                    operations.append(f"Makes API call to {child.func.attr}")

            # File Operations
            if isinstance(child, ast.With):
                if any(isinstance(exp, ast.Call) and hasattr(exp.func, 'id')
                   and exp.func.id == 'open' for exp in ast.walk(child)):
                    operations.append("Performs file operations")

            # Data Processing
            if isinstance(child, (ast.List, ast.Dict, ast.Set)):
                operations.append("Handles data structures")

            # Network Operations
            if isinstance(child, ast.Call) and hasattr(child.func, 'id'):
                if child.func.id in ['requests', 'urllib', 'socket']:
                    operations.append("Performs network operations")

        # Error Handling
            if isinstance(child, ast.Try):
                operations.append("Implements error handling")

        if not operations:
           operations.append("Basic control flow")

        return f"Function that {', '.join(set(operations)).lower()}"


    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.Try)):
                complexity += 1
        return complexity

    def _get_function_calls(self, node: ast.FunctionDef) -> List[str]:
        calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    calls.append(child.func.id)
        return calls

    def _detect_file_purpose(self) -> str:
        keywords = {
            'test': 'Unit testing module',
            'util': 'Utility functions module',
            'main': 'Main application entry point',
            'api': 'API integration module'
        }
        filename = Path(self.file_path).stem.lower()
        for key, purpose in keywords.items():
            if key in filename:
                return purpose
        return "Core functionality module"

def main():
    path = "D:\\python_work\\youtube_bot"  # Change this to your directory
    analyzer = CodebaseAnalyzer(path)

    if analyzer.is_directory:
        print("Directory Analysis:")
        analysis = analyzer.analyze_directory()
        print(analysis['system_summary'])

        print("\nIndividual File Summaries:")
        for file_path, details in analysis['relationships'].items():
            print(f"\n{file_path}:")
            print(details['summary'])
            print("\nFunction Summaries:")
            for func_name, func_details in details['functions'].items():
                print(f"\n  {func_name}:")
                print(f"    Purpose: {func_details['purpose']}")
                print(f"    Arguments: {', '.join(func_details['args'])}")
                print(f"    Complexity: {func_details['complexity']}")
                print(f"    Calls: {', '.join(func_details['calls'])}")
    else:
        print("Single File Analysis:")
        file_analyzer = analyzer.analyzers[analyzer.path]
        print(file_analyzer.generate_file_summary())
        print("\nFunction Summaries:")
        for func_name, details in file_analyzer.generate_function_summaries().items():
            print(f"\n{func_name}:")
            print(f"Purpose: {details['purpose']}")
            print(f"Arguments: {', '.join(details['args'])}")
            print(f"Complexity: {details['complexity']}")
            print(f"Calls: {', '.join(details['calls'])}")

if __name__ == "__main__":
    main()
