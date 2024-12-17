import ast
import glob
from typing import Dict, List, Tuple
from pathlib import Path
from collections import defaultdict
from code_analyzer import CodebaseAnalyzer
import networkx as nx
import matplotlib.pyplot as plt
import json
from git import Repo
import tempfile
import argparse


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





    def analyze_github_repo(self, repo_url: str):
        """Analyzes Python files from a GitHub repository"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Clone the repository
            Repo.clone_from(repo_url, temp_dir)

            # Analyze the cloned repo
            results = self.analyze_with_details()

            # Generate report
            self.save_analysis_report(results, 'github_analysis_report.md')

            return results



    def analyze_with_details(self) -> Dict:
        results = {}
        for file_path, analyzer in self.analyzers.items():
            functions = {}
            for node in ast.walk(analyzer.tree):
                if isinstance(node, ast.FunctionDef):
                    technical_analysis = analyzer._analyze_function_purpose(node)
                    functions[node.name] = {
                        'technical_details': technical_analysis,
                        'english_description': analyzer.generate_natural_language_description(technical_analysis)
                    }
            # Generate call graph for this file
            output_file = f"{Path(file_path).stem}_calls.png"
            analyzer.generate_call_graph(output_file)

            # Add file-level summary
            file_summary = analyzer.generate_file_summary(functions)
            results[file_path] = {
                'functions': functions,
                'file_summary': file_summary
            }
        return results


    def save_analysis_report(self, results, output_file='analysis_report.md'):
        with open(output_file, 'w') as f:
            f.write("# Code Analysis Report\n\n")
            for file_path, analysis in results.items():
                f.write(f"## Analysis for {file_path}\n\n")
                f.write(f"### File Summary\n{analysis['file_summary']}\n\n")
                f.write("### Function Details\n")
                for func_name, details in analysis['functions'].items():
                    f.write(f"#### {func_name}\n")
                    f.write(f"Description: {details['english_description']}\n")
                    tech_details = json.dumps(details['technical_details'], indent=2)
                    f.write(f"Technical Details:\n```json\n{tech_details}\n```\n\n")






class EnhancedSemanticAnalyzer:
    def __init__(self, file_path: str):
        self.file_path = file_path
        with open(file_path, 'r', encoding='utf-8') as file:
            self.code = file.read()
        self.tree = ast.parse(self.code)
        self.api_calls = defaultdict(list)
        self.data_flow = defaultdict(list)
        self.error_patterns = defaultdict(list)


    def generate_natural_language_description(self, analysis_data: Dict) -> str:
        """Converts technical analysis into clear English descriptions"""
        description = []

        # API Chain Description
        api_chains = analysis_data['api_hierarchy']  # Changed from 'api_chain' to 'api_hierarchy'
        if api_chains:
            description.append("This function performs the following operations:")
            for chain in api_chains:
                steps = ' -> '.join(chain['chain'])
                description.append(f"- Executes {steps}")
                if chain['args']:
                    description.append(f"  Using parameters: {', '.join(chain['args'])}")


            # Data Flow Description
        data_flows = analysis_data['data_flow']
        if data_flows:
            description.append("\nData handling:")
            for flow in data_flows:
                description.append(f"- Creates {flow['variable']} from {flow['type']}")
                description.append(f"  Used in: {flow['used_in']}")

        # Error Handling Description
        error_patterns = analysis_data['error_handling']
        if error_patterns:
            description.append("\nError management:")
            for pattern in error_patterns:
                for handler in pattern['handlers']:
                    description.append(f"- Handles {handler['exception']} errors by {handler['recovery']}")

        return '\n'.join(description)



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



    def generate_call_graph(self, output_file='function_calls.png'):
        G = nx.DiGraph()

        def visit_node(node):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    G.add_edge(current_function, node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    G.add_edge(current_function, node.func.attr)
            for child in ast.iter_child_nodes(node):
                visit_node(child)

        # Build the graph
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                current_function = node.name
                G.add_node(current_function)
                visit_node(node)

        # Create visualization
        colors = ['lightblue'] * len(G.nodes())
        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(G)
        nx.draw(G, pos, with_labels=True,
                node_color=colors,
                node_size=2000,
                font_size=10,
                font_weight='bold',
                arrows=True,
                edge_color='gray',
                arrowsize=20)

        plt.savefig(output_file)
        plt.close()



    def generate_file_summary(self, function_analyses: Dict) -> str:
        """Creates a file-level summary from individual function analyses"""
        operations = set()
        data_patterns = set()
        error_handling = set()

        for func_analysis in function_analyses.values():
            tech_details = func_analysis['technical_details']
            operations.update(tech_details['operations'])
            if tech_details['data_flow']:
                data_patterns.add('data transformation')
            if tech_details['error_handling']:
                error_handling.add('error management')

        summary = f"This module implements {len(function_analyses)} functions focusing on "
        summary += f"{', '.join(operations)}. "
        if data_patterns:
            summary += "It includes data transformation logic. "
        if error_handling:
            summary += "The module implements comprehensive error handling."

        return summary




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
        print("\nFile Summary:")
        print(enhanced_results[file_path]['file_summary'])
        print("\nFunction Details:")
        print("Basic Analysis".ljust(50) + "Enhanced Analysis")
        print("-" * 100)
        print(f"\nAnalyzing: {file_path}")


        # Compare function analysis
        basic_funcs = basic_results['relationships'][file_path]['functions']
        enhanced_funcs = enhanced_results[file_path]['functions']
        enhanced_analyzer.save_analysis_report(enhanced_results)
        for func_name in basic_funcs.keys():
            print(f"\nFunction: {func_name}")
            print(f"Basic: {basic_funcs[func_name]['purpose']}")
            print("Enhanced:")
            print(f"  Technical Details: {enhanced_funcs[func_name]['technical_details']}")
            print(f"  English Description: {enhanced_funcs[func_name]['english_description']}")




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
    path = "D:\\LongT5"
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

import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Code Analysis Tool')
    parser.add_argument('--github', type=str, help='GitHub repository URL')
    parser.add_argument('--directory', type=str, help='Local directory path')
    parser.add_argument('--file', type=str, help='Local file path')

    args = parser.parse_args()
    analyzer = EnhancedCodeAnalyzer(".")

    if args.github:
        print(f"Analyzing GitHub repo: {args.github}")
        results = analyzer.analyze_github_repo(args.github)
    elif args.directory:
        print(f"Analyzing directory: {args.directory}")
        results = analyzer.analyze_with_details()
    elif args.file:
        print(f"Analyzing file: {args.file}")
        results = analyzer.analyze_with_details()

r"""
python enhanced_analyzer.py --github https://github.com/rajeevhotmail/youtube_speechToText
python enhanced_analyzer.py --directory D:\myproject
python enhanced_analyzer.py --file D:\myproject\script.py
"""