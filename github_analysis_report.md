# Code Analysis Report

## Analysis for .\codeBERT.py

### File Summary
This module implements 3 functions focusing on Resource management, API call: decode, API call: read, API call: from_pretrained, API call: generate, API call: no_grad. It includes data transformation logic. 

### Function Details
#### setup_model
Description: This function performs the following operations:
- Executes from_pretrained
- Executes from_pretrained
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "from_pretrained"
      ],
      "args": []
    },
    {
      "chain": [
        "from_pretrained"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "API call: from_pretrained"
  ]
}
```

#### summarize_code
Description: This function performs the following operations:
- Executes decode
- Executes read
- Executes no_grad
- Executes generate

Data handling:
- Creates code from Result of read
  Used in: tokenizer
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "decode"
      ],
      "args": []
    },
    {
      "chain": [
        "read"
      ],
      "args": []
    },
    {
      "chain": [
        "no_grad"
      ],
      "args": []
    },
    {
      "chain": [
        "generate"
      ],
      "args": []
    }
  ],
  "data_flow": [
    {
      "variable": "code",
      "type": "Result of read",
      "used_in": "tokenizer"
    }
  ],
  "error_handling": [],
  "operations": [
    "Resource management",
    "API call: decode",
    "API call: read",
    "API call: generate",
    "API call: no_grad"
  ]
}
```

#### main
Description: 
Data handling:
- Creates file_path from Unknown
  Used in: summarize_code
- Creates summary from Result of summarize_code
  Used in: print
Technical Details:
```json
{
  "api_hierarchy": [],
  "data_flow": [
    {
      "variable": "file_path",
      "type": "Unknown",
      "used_in": "summarize_code"
    },
    {
      "variable": "summary",
      "type": "Result of summarize_code",
      "used_in": "print"
    }
  ],
  "error_handling": [],
  "operations": []
}
```

## Analysis for .\code_analyzer.py

### File Summary
This module implements 14 functions focusing on API call: generate_file_summary, API call: lower, API call: analyze_directory, API call: glob, API call: get_exports, API call: startswith, API call: get_dependencies, Conditional logic, API call: _calculate_complexity, API call: _analyze_function_purpose, API call: _detect_file_purpose, API call: join, API call: extend, API call: get_imports, Iteration, API call: parse, API call: append, API call: _get_function_calls, Resource management, API call: walk, API call: read, API call: generate_function_summaries, API call: generate_system_summary, API call: items. It includes data transformation logic. 

### Function Details
#### main
Description: This function performs the following operations:
- Executes analyze_directory
- Executes items
- Executes generate_function_summaries -> items
- Executes items
- Executes generate_file_summary
- Executes generate_function_summaries
- Executes join
- Executes join
- Executes join
- Executes join

Data handling:
- Creates path from Unknown
  Used in: CodebaseAnalyzer
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "analyze_directory"
      ],
      "args": []
    },
    {
      "chain": [
        "items"
      ],
      "args": []
    },
    {
      "chain": [
        "generate_function_summaries",
        "items"
      ],
      "args": []
    },
    {
      "chain": [
        "items"
      ],
      "args": []
    },
    {
      "chain": [
        "generate_file_summary"
      ],
      "args": []
    },
    {
      "chain": [
        "generate_function_summaries"
      ],
      "args": []
    },
    {
      "chain": [
        "join"
      ],
      "args": []
    },
    {
      "chain": [
        "join"
      ],
      "args": []
    },
    {
      "chain": [
        "join"
      ],
      "args": []
    },
    {
      "chain": [
        "join"
      ],
      "args": []
    }
  ],
  "data_flow": [
    {
      "variable": "path",
      "type": "Unknown",
      "used_in": "CodebaseAnalyzer"
    }
  ],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "API call: generate_file_summary",
    "API call: analyze_directory",
    "API call: generate_function_summaries",
    "API call: items",
    "API call: join",
    "Iteration"
  ]
}
```

#### __init__
Description: This function performs the following operations:
- Executes parse
- Executes read
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "parse"
      ],
      "args": []
    },
    {
      "chain": [
        "read"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "API call: read",
    "API call: parse",
    "Resource management"
  ]
}
```

#### initialize_analyzers
Description: This function performs the following operations:
- Executes glob
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "glob"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "Iteration",
    "API call: glob"
  ]
}
```

#### analyze_directory
Description: This function performs the following operations:
- Executes items
- Executes get_dependencies
- Executes generate_system_summary
  Using parameters: file_relationships
- Executes get_imports
- Executes get_exports
- Executes generate_file_summary
- Executes generate_function_summaries

Data handling:
- Creates file_relationships from Dict
  Used in: generate_system_summary
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "items"
      ],
      "args": []
    },
    {
      "chain": [
        "get_dependencies"
      ],
      "args": []
    },
    {
      "chain": [
        "generate_system_summary"
      ],
      "args": [
        "file_relationships"
      ]
    },
    {
      "chain": [
        "get_imports"
      ],
      "args": []
    },
    {
      "chain": [
        "get_exports"
      ],
      "args": []
    },
    {
      "chain": [
        "generate_file_summary"
      ],
      "args": []
    },
    {
      "chain": [
        "generate_function_summaries"
      ],
      "args": []
    }
  ],
  "data_flow": [
    {
      "variable": "file_relationships",
      "type": "Dict",
      "used_in": "generate_system_summary"
    }
  ],
  "error_handling": [],
  "operations": [
    "API call: generate_file_summary",
    "API call: get_exports",
    "API call: generate_system_summary",
    "API call: generate_function_summaries",
    "API call: items",
    "API call: get_imports",
    "Iteration",
    "API call: get_dependencies"
  ]
}
```

#### generate_system_summary
Description: This function performs the following operations:
- Executes items
- Executes items
- Executes join
  Using parameters: entry_files
- Executes join
  Using parameters: core_files
- Executes join
  Using parameters: utility_files

Data handling:
- Creates entry_files from Unknown
  Used in: join
- Creates core_files from Unknown
  Used in: join
- Creates utility_files from Unknown
  Used in: join
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "items"
      ],
      "args": []
    },
    {
      "chain": [
        "items"
      ],
      "args": []
    },
    {
      "chain": [
        "join"
      ],
      "args": [
        "entry_files"
      ]
    },
    {
      "chain": [
        "join"
      ],
      "args": [
        "core_files"
      ]
    },
    {
      "chain": [
        "join"
      ],
      "args": [
        "utility_files"
      ]
    }
  ],
  "data_flow": [
    {
      "variable": "entry_files",
      "type": "Unknown",
      "used_in": "join"
    },
    {
      "variable": "core_files",
      "type": "Unknown",
      "used_in": "join"
    },
    {
      "variable": "utility_files",
      "type": "Unknown",
      "used_in": "join"
    }
  ],
  "error_handling": [],
  "operations": [
    "API call: items",
    "API call: join"
  ]
}
```

#### get_imports
Description: This function performs the following operations:
- Executes walk
- Executes extend
- Executes append
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "walk"
      ],
      "args": []
    },
    {
      "chain": [
        "extend"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "API call: walk",
    "API call: extend",
    "Iteration",
    "API call: append"
  ]
}
```

#### get_exports
Description: This function performs the following operations:
- Executes walk
- Executes startswith
- Executes append
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "walk"
      ],
      "args": []
    },
    {
      "chain": [
        "startswith"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "API call: walk",
    "API call: startswith",
    "Iteration",
    "API call: append"
  ]
}
```

#### get_dependencies
Description: This function performs the following operations:
- Executes walk
- Executes append
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "walk"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "Iteration",
    "API call: append",
    "API call: walk"
  ]
}
```

#### generate_file_summary
Description: This function performs the following operations:
- Executes _detect_file_purpose
- Executes join
- Executes join
- Executes get_exports
- Executes get_imports
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "_detect_file_purpose"
      ],
      "args": []
    },
    {
      "chain": [
        "join"
      ],
      "args": []
    },
    {
      "chain": [
        "join"
      ],
      "args": []
    },
    {
      "chain": [
        "get_exports"
      ],
      "args": []
    },
    {
      "chain": [
        "get_imports"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "API call: get_imports",
    "API call: _detect_file_purpose",
    "API call: get_exports",
    "API call: join"
  ]
}
```

#### generate_function_summaries
Description: This function performs the following operations:
- Executes walk
- Executes _analyze_function_purpose
  Using parameters: node
- Executes _calculate_complexity
  Using parameters: node
- Executes _get_function_calls
  Using parameters: node
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "walk"
      ],
      "args": []
    },
    {
      "chain": [
        "_analyze_function_purpose"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "_calculate_complexity"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "_get_function_calls"
      ],
      "args": [
        "node"
      ]
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "API call: _calculate_complexity",
    "API call: walk",
    "API call: _analyze_function_purpose",
    "Iteration",
    "API call: _get_function_calls"
  ]
}
```

#### _analyze_function_purpose
Description: This function performs the following operations:
- Executes walk
  Using parameters: node
- Executes append
- Executes append
- Executes append
- Executes join -> lower
- Executes append
- Executes append
- Executes append
- Executes join
- Executes walk
  Using parameters: child

Data handling:
- Creates operations from List
  Used in: set
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "walk"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "join",
        "lower"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "join"
      ],
      "args": []
    },
    {
      "chain": [
        "walk"
      ],
      "args": [
        "child"
      ]
    }
  ],
  "data_flow": [
    {
      "variable": "operations",
      "type": "List",
      "used_in": "set"
    }
  ],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "API call: lower",
    "API call: walk",
    "API call: join",
    "Iteration",
    "API call: append"
  ]
}
```

#### _calculate_complexity
Description: This function performs the following operations:
- Executes walk
  Using parameters: node
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "walk"
      ],
      "args": [
        "node"
      ]
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "Iteration",
    "API call: walk"
  ]
}
```

#### _get_function_calls
Description: This function performs the following operations:
- Executes walk
  Using parameters: node
- Executes append
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "walk"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "Iteration",
    "API call: append",
    "API call: walk"
  ]
}
```

#### _detect_file_purpose
Description: This function performs the following operations:
- Executes lower
- Executes items
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "lower"
      ],
      "args": []
    },
    {
      "chain": [
        "items"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "Iteration",
    "API call: items",
    "API call: lower"
  ]
}
```

## Analysis for .\enhanced_analyzer.py

### File Summary
This module implements 23 functions focusing on API call: generate_file_summary, API call: draw, API call: generate_natural_language_description, API call: clone_from, API call: analyze_directory, API call: glob, API call: _get_call_name, API call: generate_call_graph, API call: _get_assignment_type, API call: _get_api_hierarchy, API call: dumps, API call: add_node, API call: _analyze_error_handling, API call: _get_recovery_action, API call: keys, API call: TemporaryDirectory, API call: analyze_with_details, API call: values, API call: _get_operations, API call: add_edge, Conditional logic, API call: nodes, API call: update, API call: savefig, API call: _analyze_function_purpose, API call: _get_call_args, API call: join, API call: DiGraph, API call: figure, API call: close, API call: ljust, Iteration, API call: parse, API call: append, API call: save_analysis_report, API call: _analyze_data_flow, API call: iter_child_nodes, API call: add, Resource management, API call: walk, API call: _get_try_block_info, API call: read, API call: spring_layout, API call: items, API call: _get_call_chain, API call: write. It includes data transformation logic. 

### Function Details
#### run_comparison
Description: This function performs the following operations:
- Executes analyze_directory
- Executes analyze_with_details
- Executes keys
- Executes save_analysis_report
  Using parameters: enhanced_results
- Executes keys
- Executes ljust

Data handling:
- Creates enhanced_results from Result of analyze_with_details
  Used in: save_analysis_report
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "analyze_directory"
      ],
      "args": []
    },
    {
      "chain": [
        "analyze_with_details"
      ],
      "args": []
    },
    {
      "chain": [
        "keys"
      ],
      "args": []
    },
    {
      "chain": [
        "save_analysis_report"
      ],
      "args": [
        "enhanced_results"
      ]
    },
    {
      "chain": [
        "keys"
      ],
      "args": []
    },
    {
      "chain": [
        "ljust"
      ],
      "args": []
    }
  ],
  "data_flow": [
    {
      "variable": "enhanced_results",
      "type": "Result of analyze_with_details",
      "used_in": "save_analysis_report"
    }
  ],
  "error_handling": [],
  "operations": [
    "API call: analyze_directory",
    "API call: keys",
    "API call: ljust",
    "API call: analyze_with_details",
    "Iteration",
    "API call: save_analysis_report"
  ]
}
```

#### run_combined_analysis
Description: This function performs the following operations:
- Executes analyze_directory
- Executes analyze_with_details
- Executes items
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "analyze_directory"
      ],
      "args": []
    },
    {
      "chain": [
        "analyze_with_details"
      ],
      "args": []
    },
    {
      "chain": [
        "items"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "API call: analyze_directory",
    "Iteration",
    "API call: analyze_with_details",
    "API call: items"
  ]
}
```

#### main
Description: This function performs the following operations:
- Executes items
- Executes walk
- Executes _analyze_function_purpose
  Using parameters: node
- Executes join
- Executes join

Data handling:
- Creates path from Unknown
  Used in: EnhancedCodeAnalyzer
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "items"
      ],
      "args": []
    },
    {
      "chain": [
        "walk"
      ],
      "args": []
    },
    {
      "chain": [
        "_analyze_function_purpose"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "join"
      ],
      "args": []
    },
    {
      "chain": [
        "join"
      ],
      "args": []
    }
  ],
  "data_flow": [
    {
      "variable": "path",
      "type": "Unknown",
      "used_in": "EnhancedCodeAnalyzer"
    }
  ],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "API call: walk",
    "API call: _analyze_function_purpose",
    "API call: items",
    "API call: join",
    "Iteration"
  ]
}
```

#### __init__
Description: This function performs the following operations:
- Executes parse
- Executes read
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "parse"
      ],
      "args": []
    },
    {
      "chain": [
        "read"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "API call: read",
    "API call: parse",
    "Resource management"
  ]
}
```

#### initialize_analyzers
Description: This function performs the following operations:
- Executes glob
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "glob"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "Iteration",
    "API call: glob"
  ]
}
```

#### analyze_github_repo
Description: This function performs the following operations:
- Executes TemporaryDirectory
- Executes clone_from
  Using parameters: repo_url, temp_dir
- Executes analyze_with_details
- Executes save_analysis_report
  Using parameters: results

Data handling:
- Creates results from Result of analyze_with_details
  Used in: save_analysis_report
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "TemporaryDirectory"
      ],
      "args": []
    },
    {
      "chain": [
        "clone_from"
      ],
      "args": [
        "repo_url",
        "temp_dir"
      ]
    },
    {
      "chain": [
        "analyze_with_details"
      ],
      "args": []
    },
    {
      "chain": [
        "save_analysis_report"
      ],
      "args": [
        "results"
      ]
    }
  ],
  "data_flow": [
    {
      "variable": "results",
      "type": "Result of analyze_with_details",
      "used_in": "save_analysis_report"
    }
  ],
  "error_handling": [],
  "operations": [
    "Resource management",
    "API call: clone_from",
    "API call: TemporaryDirectory",
    "API call: analyze_with_details",
    "API call: save_analysis_report"
  ]
}
```

#### analyze_with_details
Description: This function performs the following operations:
- Executes items
- Executes walk
- Executes generate_call_graph
  Using parameters: output_file
- Executes generate_file_summary
  Using parameters: functions
- Executes _analyze_function_purpose
  Using parameters: node
- Executes generate_natural_language_description
  Using parameters: technical_analysis

Data handling:
- Creates output_file from Unknown
  Used in: generate_call_graph
- Creates functions from Dict
  Used in: generate_file_summary
- Creates technical_analysis from Result of _analyze_function_purpose
  Used in: generate_natural_language_description
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "items"
      ],
      "args": []
    },
    {
      "chain": [
        "walk"
      ],
      "args": []
    },
    {
      "chain": [
        "generate_call_graph"
      ],
      "args": [
        "output_file"
      ]
    },
    {
      "chain": [
        "generate_file_summary"
      ],
      "args": [
        "functions"
      ]
    },
    {
      "chain": [
        "_analyze_function_purpose"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "generate_natural_language_description"
      ],
      "args": [
        "technical_analysis"
      ]
    }
  ],
  "data_flow": [
    {
      "variable": "output_file",
      "type": "Unknown",
      "used_in": "generate_call_graph"
    },
    {
      "variable": "functions",
      "type": "Dict",
      "used_in": "generate_file_summary"
    },
    {
      "variable": "technical_analysis",
      "type": "Result of _analyze_function_purpose",
      "used_in": "generate_natural_language_description"
    }
  ],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "API call: generate_file_summary",
    "API call: generate_natural_language_description",
    "API call: walk",
    "API call: _analyze_function_purpose",
    "API call: items",
    "API call: generate_call_graph",
    "Iteration"
  ]
}
```

#### save_analysis_report
Description: This function performs the following operations:
- Executes write
- Executes items
- Executes write
- Executes write
- Executes write
- Executes items
- Executes write
- Executes write
- Executes dumps
- Executes write
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "write"
      ],
      "args": []
    },
    {
      "chain": [
        "items"
      ],
      "args": []
    },
    {
      "chain": [
        "write"
      ],
      "args": []
    },
    {
      "chain": [
        "write"
      ],
      "args": []
    },
    {
      "chain": [
        "write"
      ],
      "args": []
    },
    {
      "chain": [
        "items"
      ],
      "args": []
    },
    {
      "chain": [
        "write"
      ],
      "args": []
    },
    {
      "chain": [
        "write"
      ],
      "args": []
    },
    {
      "chain": [
        "dumps"
      ],
      "args": []
    },
    {
      "chain": [
        "write"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "API call: dumps",
    "Resource management",
    "API call: items",
    "API call: write",
    "Iteration"
  ]
}
```

#### generate_natural_language_description
Description: This function performs the following operations:
- Executes join
  Using parameters: description
- Executes append
- Executes append
- Executes append
- Executes join
- Executes append
- Executes append
- Executes append
- Executes append
- Executes append
- Executes join

Data handling:
- Creates description from List
  Used in: join
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "join"
      ],
      "args": [
        "description"
      ]
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "join"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "join"
      ],
      "args": []
    }
  ],
  "data_flow": [
    {
      "variable": "description",
      "type": "List",
      "used_in": "join"
    }
  ],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "Iteration",
    "API call: join",
    "API call: append"
  ]
}
```

#### _analyze_function_purpose
Description: This function performs the following operations:
- Executes _get_api_hierarchy
  Using parameters: node
- Executes _analyze_data_flow
  Using parameters: node
- Executes _analyze_error_handling
  Using parameters: node
- Executes _get_operations
  Using parameters: node
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "_get_api_hierarchy"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "_analyze_data_flow"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "_analyze_error_handling"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "_get_operations"
      ],
      "args": [
        "node"
      ]
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "API call: _get_operations",
    "API call: _analyze_data_flow",
    "API call: _analyze_error_handling",
    "API call: _get_api_hierarchy"
  ]
}
```

#### _get_api_hierarchy
Description: This function performs the following operations:
- Executes walk
  Using parameters: node
- Executes _get_call_chain
  Using parameters: child
- Executes append
- Executes _get_call_args
  Using parameters: child
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "walk"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "_get_call_chain"
      ],
      "args": [
        "child"
      ]
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "_get_call_args"
      ],
      "args": [
        "child"
      ]
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "API call: walk",
    "API call: _get_call_args",
    "API call: _get_call_chain",
    "Iteration",
    "API call: append"
  ]
}
```

#### _get_call_chain
Description: This function performs the following operations:
- Executes append

Data handling:
- Creates current from Unknown
  Used in: hasattr
- Creates chain from List
  Used in: reversed
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "append"
      ],
      "args": []
    }
  ],
  "data_flow": [
    {
      "variable": "current",
      "type": "Unknown",
      "used_in": "hasattr"
    },
    {
      "variable": "chain",
      "type": "List",
      "used_in": "reversed"
    }
  ],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "Iteration",
    "API call: append"
  ]
}
```

#### _analyze_data_flow
Description: This function performs the following operations:
- Executes walk
  Using parameters: node
- Executes _get_assignment_type
- Executes _get_call_args
  Using parameters: child
- Executes append
- Executes _get_call_name
  Using parameters: child
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "walk"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "_get_assignment_type"
      ],
      "args": []
    },
    {
      "chain": [
        "_get_call_args"
      ],
      "args": [
        "child"
      ]
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "_get_call_name"
      ],
      "args": [
        "child"
      ]
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "API call: walk",
    "API call: _get_call_args",
    "API call: _get_call_name",
    "Iteration",
    "API call: append",
    "API call: _get_assignment_type"
  ]
}
```

#### _analyze_error_handling
Description: This function performs the following operations:
- Executes walk
  Using parameters: node
- Executes append
- Executes append
- Executes _get_try_block_info
- Executes _get_recovery_action
  Using parameters: handler
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "walk"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "_get_try_block_info"
      ],
      "args": []
    },
    {
      "chain": [
        "_get_recovery_action"
      ],
      "args": [
        "handler"
      ]
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "API call: _get_recovery_action",
    "API call: walk",
    "API call: _get_try_block_info",
    "Iteration",
    "API call: append"
  ]
}
```

#### _get_operations
Description: This function performs the following operations:
- Executes walk
  Using parameters: node
- Executes append
- Executes append
- Executes append
- Executes append

Data handling:
- Creates operations from List
  Used in: set
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "walk"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    }
  ],
  "data_flow": [
    {
      "variable": "operations",
      "type": "List",
      "used_in": "set"
    }
  ],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "Iteration",
    "API call: append",
    "API call: walk"
  ]
}
```

#### _get_assignment_type
Description: This function performs the following operations:
- Executes _get_call_name
  Using parameters: node
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "_get_call_name"
      ],
      "args": [
        "node"
      ]
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "API call: _get_call_name"
  ]
}
```

#### _get_call_name
Description: 
Technical Details:
```json
{
  "api_hierarchy": [],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic"
  ]
}
```

#### _get_call_args
Description: This function performs the following operations:
- Executes append
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "append"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "Iteration",
    "API call: append"
  ]
}
```

#### _get_recovery_action
Description: This function performs the following operations:
- Executes join
  Using parameters: actions
- Executes append

Data handling:
- Creates actions from List
  Used in: join
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "join"
      ],
      "args": [
        "actions"
      ]
    },
    {
      "chain": [
        "append"
      ],
      "args": []
    }
  ],
  "data_flow": [
    {
      "variable": "actions",
      "type": "List",
      "used_in": "join"
    }
  ],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "Iteration",
    "API call: join",
    "API call: append"
  ]
}
```

#### _get_try_block_info
Description: This function performs the following operations:
- Executes append
- Executes _get_call_name
  Using parameters: node
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "append"
      ],
      "args": []
    },
    {
      "chain": [
        "_get_call_name"
      ],
      "args": [
        "node"
      ]
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "Iteration",
    "API call: _get_call_name",
    "API call: append"
  ]
}
```

#### generate_call_graph
Description: This function performs the following operations:
- Executes DiGraph
- Executes walk
- Executes figure
- Executes spring_layout
  Using parameters: G
- Executes draw
  Using parameters: G, pos
- Executes savefig
  Using parameters: output_file
- Executes close
- Executes iter_child_nodes
  Using parameters: node
- Executes add_node
  Using parameters: current_function
- Executes nodes
- Executes add_edge
  Using parameters: current_function
- Executes add_edge
  Using parameters: current_function

Data handling:
- Creates G from Result of DiGraph
  Used in: spring_layout
- Creates G from Result of DiGraph
  Used in: draw
- Creates pos from Result of spring_layout
  Used in: draw
- Creates current_function from Unknown
  Used in: add_node
- Creates current_function from Unknown
  Used in: add_edge
- Creates current_function from Unknown
  Used in: add_edge
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "DiGraph"
      ],
      "args": []
    },
    {
      "chain": [
        "walk"
      ],
      "args": []
    },
    {
      "chain": [
        "figure"
      ],
      "args": []
    },
    {
      "chain": [
        "spring_layout"
      ],
      "args": [
        "G"
      ]
    },
    {
      "chain": [
        "draw"
      ],
      "args": [
        "G",
        "pos"
      ]
    },
    {
      "chain": [
        "savefig"
      ],
      "args": [
        "output_file"
      ]
    },
    {
      "chain": [
        "close"
      ],
      "args": []
    },
    {
      "chain": [
        "iter_child_nodes"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "add_node"
      ],
      "args": [
        "current_function"
      ]
    },
    {
      "chain": [
        "nodes"
      ],
      "args": []
    },
    {
      "chain": [
        "add_edge"
      ],
      "args": [
        "current_function"
      ]
    },
    {
      "chain": [
        "add_edge"
      ],
      "args": [
        "current_function"
      ]
    }
  ],
  "data_flow": [
    {
      "variable": "G",
      "type": "Result of DiGraph",
      "used_in": "spring_layout"
    },
    {
      "variable": "G",
      "type": "Result of DiGraph",
      "used_in": "draw"
    },
    {
      "variable": "pos",
      "type": "Result of spring_layout",
      "used_in": "draw"
    },
    {
      "variable": "current_function",
      "type": "Unknown",
      "used_in": "add_node"
    },
    {
      "variable": "current_function",
      "type": "Unknown",
      "used_in": "add_edge"
    },
    {
      "variable": "current_function",
      "type": "Unknown",
      "used_in": "add_edge"
    }
  ],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "API call: draw",
    "API call: add_node",
    "API call: iter_child_nodes",
    "API call: nodes",
    "API call: savefig",
    "API call: walk",
    "API call: spring_layout",
    "API call: DiGraph",
    "API call: figure",
    "API call: close",
    "Iteration",
    "API call: add_edge"
  ]
}
```

#### generate_file_summary
Description: This function performs the following operations:
- Executes values
- Executes update
- Executes add
- Executes add
- Executes join
  Using parameters: operations

Data handling:
- Creates operations from Result of set
  Used in: join
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "values"
      ],
      "args": []
    },
    {
      "chain": [
        "update"
      ],
      "args": []
    },
    {
      "chain": [
        "add"
      ],
      "args": []
    },
    {
      "chain": [
        "add"
      ],
      "args": []
    },
    {
      "chain": [
        "join"
      ],
      "args": [
        "operations"
      ]
    }
  ],
  "data_flow": [
    {
      "variable": "operations",
      "type": "Result of set",
      "used_in": "join"
    }
  ],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "API call: update",
    "API call: add",
    "API call: join",
    "API call: values",
    "Iteration"
  ]
}
```

#### visit_node
Description: This function performs the following operations:
- Executes iter_child_nodes
  Using parameters: node
- Executes add_edge
  Using parameters: current_function
- Executes add_edge
  Using parameters: current_function
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "iter_child_nodes"
      ],
      "args": [
        "node"
      ]
    },
    {
      "chain": [
        "add_edge"
      ],
      "args": [
        "current_function"
      ]
    },
    {
      "chain": [
        "add_edge"
      ],
      "args": [
        "current_function"
      ]
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "Conditional logic",
    "Iteration",
    "API call: iter_child_nodes",
    "API call: add_edge"
  ]
}
```

## Analysis for .\main.py

### File Summary
This module implements 2 functions focusing on API call: create, API call: read, Resource management. It includes data transformation logic. 

### Function Details
#### summarize_code
Description: This function performs the following operations:
- Executes create
- Executes read
Technical Details:
```json
{
  "api_hierarchy": [
    {
      "chain": [
        "create"
      ],
      "args": []
    },
    {
      "chain": [
        "read"
      ],
      "args": []
    }
  ],
  "data_flow": [],
  "error_handling": [],
  "operations": [
    "API call: create",
    "API call: read",
    "Resource management"
  ]
}
```

#### main
Description: 
Data handling:
- Creates file_path from Unknown
  Used in: summarize_code
- Creates summary from Result of summarize_code
  Used in: print
Technical Details:
```json
{
  "api_hierarchy": [],
  "data_flow": [
    {
      "variable": "file_path",
      "type": "Unknown",
      "used_in": "summarize_code"
    },
    {
      "variable": "summary",
      "type": "Result of summarize_code",
      "used_in": "print"
    }
  ],
  "error_handling": [],
  "operations": []
}
```

