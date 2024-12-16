import ast
import glob
from typing import Dict, List, Tuple
from pathlib import Path
from collections import defaultdict
from code_analyzer import CodebaseAnalyzer


class EnhancedCodeAnalyzer:
    def __init__(self, path: str):
        self.path = path
        self.is_directory = Path(path).is_dir()
        self.analyzers = {}
        self.initialize_analyzers()

    def initialize_analyzers(self):
        if self.is_directory:
            for file in glob.glob(f"{self.path}/*.py"):
                self.analyzers[file] = EnhancedSemanticAnalyzer(file)
        else:
            self.analyzers[self.path] = EnhancedSemanticAnalyzer(self.path)

    def analyze_with_details(self) -> Dict:
        results = {}
        for file_path, analyzer in self.analyzers.items():
            functions = {}
            for node in ast.walk(analyzer.tree):
                if isinstance(node, ast.FunctionDef):
                    functions[node.name] = analyzer._analyze_function_purpose(node)
            results[file_path] = {'functions': functions}
        return results




class EnhancedSemanticAnalyzer:
    def __init__(self, file_path: str):
        self.file_path = file_path
        with open(file_path, 'r', encoding='utf-8') as file:
            self.code = file.read()
        self.tree = ast.parse(self.code)
        self.api_calls = defaultdict(list)
        self.data_flow = defaultdict(list)
        self.error_patterns = defaultdict(list)

    def _analyze_function_purpose(self, node: ast.FunctionDef) -> Dict:
        analysis = {
            'api_hierarchy': self._get_api_hierarchy(node),
            'data_flow': self._analyze_data_flow(node),
            'error_handling': self._analyze_error_handling(node),
            'operations': self._get_operations(node)
        }
        return analysis

    def _get_api_hierarchy(self, node: ast.FunctionDef) -> List[Dict]:
        api_calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if hasattr(child.func, 'attr'):
                    call_chain = self._get_call_chain(child)
                    api_calls.append({
                        'chain': call_chain,
                        'args': self._get_call_args(child)
                    })
        return api_calls

    def _get_call_chain(self, node: ast.Call) -> List[str]:
        chain = []
        current = node
        while hasattr(current, 'func'):
            if hasattr(current.func, 'attr'):
                chain.append(current.func.attr)
            if hasattr(current.func, 'value'):
                current = current.func.value
            else:
                break
        return list(reversed(chain))

    def _analyze_data_flow(self, node: ast.FunctionDef) -> List[Dict]:
        flow = []
        var_assignments = {}

        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                targets = [t.id for t in child.targets if isinstance(t, ast.Name)]
                if targets:
                    var_assignments[targets[0]] = self._get_assignment_type(child.value)
            elif isinstance(child, ast.Call):
                args = self._get_call_args(child)
                for arg in args:
                    if arg in var_assignments:
                        flow.append({
                            'variable': arg,
                            'type': var_assignments[arg],
                            'used_in': self._get_call_name(child)
                        })
        return flow

    def _analyze_error_handling(self, node: ast.FunctionDef) -> List[Dict]:
        error_patterns = []
        for child in ast.walk(node):
            if isinstance(child, ast.Try):
                handlers = []
                for handler in child.handlers:
                    if isinstance(handler.type, ast.Name):
                        handlers.append({
                            'exception': handler.type.id,
                            'recovery': self._get_recovery_action(handler)
                        })
                error_patterns.append({
                    'protected_code': self._get_try_block_info(child.body),
                    'handlers': handlers
                })
        return error_patterns

    def _get_operations(self, node: ast.FunctionDef) -> List[str]:
        operations = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if hasattr(child.func, 'attr'):
                    operations.append(f"API call: {child.func.attr}")
            elif isinstance(child, ast.With):
                operations.append("Resource management")
            elif isinstance(child, (ast.For, ast.While)):
                operations.append("Iteration")
            elif isinstance(child, ast.If):
                operations.append("Conditional logic")
        return list(set(operations))

    def _get_assignment_type(self, node) -> str:
        if isinstance(node, ast.Call):
            return f"Result of {self._get_call_name(node)}"
        elif isinstance(node, (ast.List, ast.Dict, ast.Set)):
            return node.__class__.__name__
        return "Unknown"

    def _get_call_name(self, node: ast.Call) -> str:
        if hasattr(node.func, 'attr'):
            return node.func.attr
        elif hasattr(node.func, 'id'):
            return node.func.id
        return "unknown_call"

    def _get_call_args(self, node: ast.Call) -> List[str]:
        args = []
        for arg in node.args:
            if isinstance(arg, ast.Name):
                args.append(arg.id)
        return args

    def _get_recovery_action(self, handler: ast.ExceptHandler) -> str:
        actions = []
        for node in handler.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                if hasattr(node.value.func, 'id'):
                    actions.append(node.value.func.id)
        return ', '.join(actions) if actions else "pass"

    def _get_try_block_info(self, body) -> List[str]:
        operations = []
        for node in body:
            if isinstance(node, ast.Call):
                operations.append(self._get_call_name(node))
        return operations

def run_comparison(directory_path: str):
    print("=== Basic Analysis ===")
    basic_analyzer = CodebaseAnalyzer(directory_path)
    basic_results = basic_analyzer.analyze_directory()

    print("\n=== Enhanced Analysis ===")
    enhanced_analyzer = EnhancedCodeAnalyzer(directory_path)
    enhanced_results = enhanced_analyzer.analyze_with_details()

    # Display side-by-side comparison for each file
    for file_path in basic_results['relationships'].keys():
        print(f"\nAnalyzing: {file_path}")
        print("Basic Analysis".ljust(50) + "Enhanced Analysis")
        print("-" * 100)

        # Compare function analysis
        basic_funcs = basic_results['relationships'][file_path]['functions']
        enhanced_funcs = enhanced_results[file_path]['functions']

        for func_name in basic_funcs.keys():
            print(f"\nFunction: {func_name}")
            print(f"Basic: {basic_funcs[func_name]['purpose']}")
            print("Enhanced:")
            print(f"  API Chain: {enhanced_funcs[func_name]['api_hierarchy']}")
            print(f"  Data Flow: {enhanced_funcs[func_name]['data_flow']}")
            print(f"  Error Handling: {enhanced_funcs[func_name]['error_handling']}")




def run_combined_analysis(directory_path: str):
    # Run basic analyzer
    basic_analyzer = CodebaseAnalyzer(directory_path)
    basic_results = basic_analyzer.analyze_directory()

    # Run enhanced analyzer
    enhanced_analyzer = EnhancedCodeAnalyzer(directory_path)
    enhanced_results = enhanced_analyzer.analyze_with_details()

    # Combine and present results
    print("=== System Level Analysis ===")
    print(basic_results['system_summary'])

    print("\n=== Detailed Function Analysis ===")
    for file_path, analysis in enhanced_results.items():
        print(f"\nFile: {file_path}")
        print("API Hierarchies:")
        print(analysis['api_chains'])
        print("\nData Flows:")
        print(analysis['data_flows'])
        print("\nError Handling Patterns:")
        print(analysis['error_patterns'])

def main():
    path = "D:\\python_work\\youtube_bot"
    analyzer = EnhancedCodeAnalyzer(path)

    for file_path, semantic_analyzer in analyzer.analyzers.items():
        print(f"\nAnalyzing {file_path}:")
        for node in ast.walk(semantic_analyzer.tree):
            if isinstance(node, ast.FunctionDef):
                analysis = semantic_analyzer._analyze_function_purpose(node)
                print(f"\nFunction: {node.name}")
                print("API Hierarchy:")
                for call in analysis['api_hierarchy']:
                    print(f"  Chain: {' -> '.join(call['chain'])}")
                    print(f"  Arguments: {call['args']}")
                print("\nData Flow:")
                for flow in analysis['data_flow']:
                    print(f"  {flow['variable']} ({flow['type']}) -> {flow['used_in']}")
                print("\nError Handling:")
                for pattern in analysis['error_handling']:
                    print(f"  Protected operations: {pattern['protected_code']}")
                    for handler in pattern['handlers']:
                        print(f"  Handles {handler['exception']} with {handler['recovery']}")
                print("\nOperations:", ', '.join(analysis['operations']))

if __name__ == "__main__":
    #run_comparison("D:\\python_work\\youtube_bot")
    run_comparison("D:\\LongT5")

