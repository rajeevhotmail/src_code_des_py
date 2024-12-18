from enhanced_analyzer import EnhancedSemanticAnalyzer
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



class ASTLLMAnalyzer:
    def __init__(self, ast_tree):
        self.ast_tree = ast_tree
        self.structured_info = self.prepare_ast_structure()

    def prepare_ast_structure(self):
        return {
            'imports': self.extract_imports(),
            'functions': self.extract_functions(),
            'classes': self.extract_classes(),
            'control_flow': self.analyze_control_flow()
        }

    def extract_imports(self):
        imports = []
        for node in ast.walk(self.ast_tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imports.append(self.format_import(node))
        return imports



    def extract_functions(self):
        functions = []
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.FunctionDef):
                function_info = {
                    'name': node.name,
                    'args': self.extract_arguments(node),
                    'body_type': self.analyze_body_type(node),
                    'complexity': self.analyze_complexity(node)
                }
                functions.append(function_info)
        return functions

    def extract_arguments(self, node):
        return [arg.arg for arg in node.args.args]

    def analyze_body_type(self, node):
        body_types = set()
        for stmt in node.body:
            if isinstance(stmt, ast.Call):
                body_types.add('api_call')
            elif isinstance(stmt, ast.If):
                body_types.add('conditional')
            elif isinstance(stmt, (ast.For, ast.While)):
                body_types.add('loop')
        return list(body_types)


    def analyze_complexity(self, node):
        """Analyzes cognitive complexity of function"""
        complexity = 0
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For)):
                complexity += 1
            elif isinstance(child, ast.Try):
                complexity += len(child.handlers)
        return complexity

    def extract_classes(self):
        classes = []
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.ClassDef):
                class_info = {
                    'name': node.name,
                    'methods': self.extract_methods(node),
                    'attributes': self.extract_attributes(node),
                    'inheritance': [base.id for base in node.bases if isinstance(base, ast.Name)]
                }
                classes.append(class_info)
        return classes

    def analyze_control_flow(self):
        """Maps the control flow patterns in the code"""
        flow_patterns = {
            'conditionals': [],
            'loops': [],
            'error_handling': []
        }
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.If):
                flow_patterns['conditionals'].append(self.analyze_conditional(node))
            elif isinstance(node, (ast.For, ast.While)):
                flow_patterns['loops'].append(self.analyze_loop(node))
        return flow_patterns

    def analyze_conditional(self, node):
        """Extracts meaningful information from conditional statements"""
        return {
            'test_type': self.classify_test(node.test),
            'has_else': bool(node.orelse),
            'nested_depth': self.get_nesting_depth(node)
        }

    def analyze_loop(self, node):
        """Analyzes loop structures and their purpose"""
        return {
            'type': 'for' if isinstance(node, ast.For) else 'while',
            'target': self.extract_loop_target(node),
            'contains_break': self.has_break(node),
            'contains_continue': self.has_continue(node)
        }

    def format_for_llm(self):
        """Prepares AST analysis in LLM-friendly format"""
        return {
            'code_structure': self.structured_info,
            'complexity_metrics': self.calculate_metrics(),
            'semantic_patterns': self.identify_patterns()
        }

    def classify_test(self, test_node):
        """Identifies the type of conditional test"""
        if isinstance(test_node, ast.Compare):
            return {
                'type': 'comparison',
                'ops': [type(op).__name__ for op in test_node.ops]
            }
        elif isinstance(test_node, ast.BoolOp):
            return {
                'type': 'boolean_operation',
                'op': type(test_node.op).__name__
            }
        return {'type': 'other'}

    def get_nesting_depth(self, node, depth=0):
        """Calculates the nesting depth of a node"""
        parent = getattr(node, 'parent', None)
        while parent:
            if isinstance(parent, (ast.If, ast.For, ast.While)):
                depth += 1
            parent = getattr(parent, 'parent', None)
        return depth

    def extract_loop_target(self, node):
        """Extracts information about loop iteration targets"""
        if isinstance(node, ast.For):
            return {
                'type': 'iterator',
                'target': self.format_node(node.target)
            }
        return {
            'type': 'while_condition',
            'condition': self.format_node(node.test)
        }


        def calculate_metrics(self):
            """Calculates code complexity and maintainability metrics"""
        return {
            'cyclomatic_complexity': self.calculate_cyclomatic_complexity(),
            'cognitive_load': self.calculate_cognitive_load(),
            'maintainability_index': self.calculate_maintainability()
        }

    def identify_patterns(self):
        """Identifies common code patterns and design patterns"""
        return {
            'design_patterns': self.detect_design_patterns(),
            'api_patterns': self.analyze_api_usage(),
            'data_patterns': self.analyze_data_structures()
        }

    def format_node(self, node):
        """Formats AST node into LLM-friendly structure"""
        if isinstance(node, ast.Name):
            return {'type': 'name', 'id': node.id}
        elif isinstance(node, ast.Call):
            return {
                'type': 'call',
                'function': self.format_node(node.func),
                'args': [self.format_node(arg) for arg in node.args]
            }
        return {'type': 'unknown'}

    def detect_design_patterns(self):
        """Detects common design patterns in the code"""
        patterns = {
            'singleton': self.detect_singleton(),
            'factory': self.detect_factory_pattern(),
            'observer': self.detect_observer_pattern()
        }
        return {k: v for k, v in patterns.items() if v}

    def analyze_api_usage(self):
        """Analyzes API usage patterns"""
        return {
            'external_calls': self.collect_external_calls(),
            'libraries': self.collect_used_libraries(),
            'common_patterns': self.identify_api_patterns()
        }

    def analyze_data_structures(self):
        """Analyzes data structure usage and patterns"""
        return {
            'collections': self.analyze_collections(),
            'custom_types': self.analyze_custom_types(),
            'data_flow': self.analyze_data_flow_patterns()
        }


    def format_import(self, node):
        """Formats import statements into structured data"""
        if isinstance(node, ast.Import):
            return {
                'type': 'import',
                'names': [name.name for name in node.names]
            }
        elif isinstance(node, ast.ImportFrom):
            return {
                'type': 'import_from',
                'module': node.module,
                'names': [name.name for name in node.names]
            }

    def has_break(self, node):
        """Checks if a loop contains break statements"""
        return any(isinstance(n, ast.Break) for n in ast.walk(node))

    def has_continue(self, node):
        """Checks if a loop contains continue statements"""
        return any(isinstance(n, ast.Continue) for n in ast.walk(node))


    def calculate_metrics(self):
        """Calculates code complexity and maintainability metrics"""
        return {
            'cyclomatic_complexity': self.calculate_cyclomatic_complexity(),
            'cognitive_load': self.calculate_cognitive_load(),
            'maintainability_index': self.calculate_maintainability()
        }

    def calculate_cyclomatic_complexity(self):
        """Calculates cyclomatic complexity"""
        complexity = 1  # Base complexity
        for node in ast.walk(self.ast_tree):
            if isinstance(node, (ast.If, ast.While, ast.For)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1
        return complexity

    def calculate_cognitive_load(self):
        """Calculates cognitive load based on nesting and operations"""
        load = 0
        for node in ast.walk(self.ast_tree):
            if isinstance(node, (ast.If, ast.While, ast.For)):
                load += 1 + self.get_nesting_depth(node)
        return load

    def calculate_maintainability(self):
        """Calculates maintainability index"""
        return {
            'nested_structures': self.count_nested_structures(),
            'average_function_length': self.average_function_length()
        }


    def count_nested_structures(self):
        """Counts nested control structures"""
        nested_count = 0
        for node in ast.walk(self.ast_tree):
            if isinstance(node, (ast.If, ast.For, ast.While)):
                depth = self.get_nesting_depth(node)
                if depth > 0:
                    nested_count += 1
        return nested_count

    def average_function_length(self):
        """Calculates average function length in lines"""
        lengths = []
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.FunctionDef):
                lengths.append(len(node.body))
        return sum(lengths) / len(lengths) if lengths else 0

    def detect_singleton(self):
        """Detects singleton pattern implementation"""
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.ClassDef):
                has_private_constructor = False
                has_instance_var = False
                for child in node.body:
                    if isinstance(child, ast.FunctionDef) and child.name == '__init__':
                        has_private_constructor = True
                    if isinstance(child, ast.Assign):
                        has_instance_var = True
                if has_private_constructor and has_instance_var:
                    return True
        return False

    def detect_factory_pattern(self):
        """Detects factory pattern implementation"""
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, ast.FunctionDef) and 'create' in child.name.lower():
                        return True
        return False

    def detect_observer_pattern(self):
        """Detects observer pattern implementation"""
        has_observers = False
        has_notify = False
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, ast.FunctionDef):
                        if 'notify' in child.name.lower():
                            has_notify = True
                        if 'observer' in child.name.lower():
                            has_observers = True
        return has_notify and has_observers

    def collect_external_calls(self):
        """Collects all external API calls"""
        external_calls = []
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    external_calls.append({
                        'module': self.get_module_name(node.func),
                        'function': node.func.attr
                    })
        return external_calls

    def collect_used_libraries(self):
        """Identifies all used external libraries"""
        libraries = set()
        for node in ast.walk(self.ast_tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for name in node.names:
                    libraries.add(name.name.split('.')[0])
        return list(libraries)

    def identify_api_patterns(self):
        """Identifies common API usage patterns"""
        return {
            'file_operations': self.detect_file_operations(),
            'network_calls': self.detect_network_calls(),
            'database_operations': self.detect_database_operations()
        }

    def get_module_name(self, node):
        """Extracts module name from attribute call"""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return '.'.join(reversed(parts))


    def detect_file_operations(self):
        """Detects file handling operations"""
        file_ops = {
            'read': False,
            'write': False,
            'open': False
        }
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id == 'open':
                        file_ops['open'] = True
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr in ['read', 'write']:
                        file_ops[node.func.attr] = True
        return file_ops

    def detect_network_calls(self):
        """Detects network-related operations"""
        network_patterns = ['requests', 'urllib', 'http', 'socket']
        return any(
            lib in str(node.names[0].name)
            for node in ast.walk(self.ast_tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for lib in network_patterns
        )

    def detect_database_operations(self):
           """Detects database operations"""
           db_patterns = ['sql', 'database', 'mongo', 'redis']
           return any(
               lib in str(node.names[0].name).lower()
               for node in ast.walk(self.ast_tree)
               if isinstance(node, (ast.Import, ast.ImportFrom))
               for lib in db_patterns
           )


    def analyze_collections(self):
        """Analyzes usage of Python collections"""
        collections = {
            'list': 0,
            'dict': 0,
            'set': 0,
            'tuple': 0
        }
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.List):
                collections['list'] += 1
            elif isinstance(node, ast.Dict):
                collections['dict'] += 1
            elif isinstance(node, ast.Set):
                collections['set'] += 1
            elif isinstance(node, ast.Tuple):
                collections['tuple'] += 1
        return collections

    def analyze_custom_types(self):
        """Analyzes custom type definitions"""
        return [
            node.name
            for node in ast.walk(self.ast_tree)
            if isinstance(node, ast.ClassDef)
        ]

    def analyze_data_flow_patterns(self):
        """Analyzes data transformation patterns"""
        patterns = {
            'transformations': self.detect_transformations(),
            'aggregations': self.detect_aggregations(),
            'filtering': self.detect_filtering()
        }
        return patterns

    def detect_transformations(self):
        """Detects data transformation operations"""
        transform_ops = ['map', 'filter', 'reduce', 'comprehension']
        return [op for op in transform_ops if self.has_operation(op)]

    def detect_aggregations(self):
        """Detects data aggregation operations"""
        agg_funcs = ['sum', 'max', 'min', 'avg', 'count']
        return [func for func in agg_funcs if self.has_function_call(func)]

    def detect_filtering(self):
        """Detects data filtering operations"""
        return any(
            isinstance(node, ast.ListComp) or
            (isinstance(node, ast.Call) and
            isinstance(node.func, ast.Name) and
            node.func.id == 'filter')
            for node in ast.walk(self.ast_tree)
        )

    def has_operation(self, operation_name):
        """Checks if specific operation exists in code"""
        return any(
            isinstance(node, ast.Call) and
            hasattr(node.func, 'id') and
            node.func.id == operation_name
            for node in ast.walk(self.ast_tree)
        )

    def has_function_call(self, function_name):
        """Checks if specific function is called"""
        return any(
            isinstance(node, ast.Call) and
            hasattr(node.func, 'id') and
            node.func.id == function_name
            for node in ast.walk(self.ast_tree)
        )




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
    test_path = "D:\\LongT5"
    for file in glob.glob(f"{test_path}/*.py"):
        with open(file, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read())
            analyzer = ASTLLMAnalyzer(tree)
            results = analyzer.format_for_llm()
            print(f"\nAnalysis for {file}:")
            print(json.dumps(results, indent=2))


r"""
python enhanced_analyzer.py --github https://github.com/rajeevhotmail/youtube_speechToText
python enhanced_analyzer.py --directory D:\myproject
python enhanced_analyzer.py --file D:\myproject\script.py
"""