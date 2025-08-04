#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import argparse
import os
import glob
from collections import defaultdict, Counter
from pathlib import Path

class CFunctionAnalyzer:
    def __init__(self):
        # Keywords for C language, would ingore them all
        self.c_keywords = {
            'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do',
            'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if',
            'int', 'long', 'register', 'return', 'short', 'signed', 'sizeof', 'static',
            'struct', 'switch', 'typedef', 'union', 'unsigned', 'void', 'volatile', 'while',
            'inline', 'restrict', '_Bool', '_Complex', '_Imaginary'
        }

        # Config file
        self.components = []        # For [component]
        self.scopes = []            # For [scope]
        self.ignores = []           # For [ignore]
        self.share_resources = []   # For [share_resource]

        # Analyzed result
        self.all_files = []                     # All files to be analyzed, i.e. scopes - ignores
        self.component_files = set()            # All files for the "component" set
        self.out_of_component_files = set()     # All files for the "out of the component" set

        # Function info - use filepath as key for dictionary
        self.file_functions = defaultdict(dict)             # {file_path: {func_name: func_info}}
        self.function_locations = defaultdict(list)         # {func_name: [(file_path, line_num)]}
        self.call_locations = defaultdict(list)             # {(caller, callee): [(file_path, line_num)]}
        # Share resource access info
        self.function_resource_access = defaultdict(set)    # {func_name: set(accessed_resources)}
        self.resource_access_details = defaultdict(list)    # {func_name: [(resource, file_path, access_type)]}

        # 舊的資料結構保留相容性
        self.interfaces = set()
        self.callees = set()
        self.callers = set()
        self.caller_definitions = {}
        self.call_relationships = defaultdict(list)
        self.callee_count = Counter()

    def parse_config_file(self, config_path):
        """Parsing config file"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(config_path, 'r', encoding='latin-1') as f:
                content = f.read()

        # Remove C-style comments in config file
        content = self.remove_comments_and_strings(content)

        # Parsing for component
        component_pattern = r'\[component\](.*?)\[/component\]'
        component_matches = re.findall(component_pattern, content, re.DOTALL | re.IGNORECASE)
        for match in component_matches:
            paths = [line.strip() for line in match.strip().split('\n') if line.strip()]
            self.components.extend(paths)

        # Parsing for scope
        scope_pattern = r'\[scope\](.*?)\[/scope\]'
        scope_matches = re.findall(scope_pattern, content, re.DOTALL | re.IGNORECASE)
        for match in scope_matches:
            paths = [line.strip() for line in match.strip().split('\n') if line.strip()]
            self.scopes.extend(paths)

        # Parsing for ignore
        ignore_pattern = r'\[ignore\](.*?)\[/ignore\]'
        ignore_matches = re.findall(ignore_pattern, content, re.DOTALL | re.IGNORECASE)
        for match in ignore_matches:
            paths = [line.strip() for line in match.strip().split('\n') if line.strip()]
            self.ignores.extend(paths)

        # Parsing for share_resource
        share_resource_pattern = r'\[share_resource\](.*?)\[/share_resource\]'
        share_resource_matches = re.findall(share_resource_pattern, content, re.DOTALL | re.IGNORECASE)
        for match in share_resource_matches:
            resources = [line.strip() for line in match.strip().split('\n') if line.strip()]
            self.share_resources.extend(resources)

    def collect_files_to_analyze(self):
        """Collect files to analyze"""
        all_scope_files = set()

        # Collect all .c files from [scope] tag
        for scope_path in self.scopes:
            if os.path.isdir(scope_path):
                # Recursive find all .c files if it's a folder
                c_files = glob.glob(os.path.join(scope_path, '**', '*.c'), recursive=True)
                all_scope_files.update(c_files)
            elif scope_path.endswith('.c') and os.path.isfile(scope_path):
                # If it's a single .c file
                all_scope_files.add(scope_path)

        # Remove files listed in [ignore] tag
        files_to_ignore = set()
        for ignore_path in self.ignores:
            if os.path.isdir(ignore_path):
                # Ignore all .c files if it's a folder
                c_files = glob.glob(os.path.join(ignore_path, '**', '*.c'), recursive=True)
                files_to_ignore.update(c_files)
            elif ignore_path.endswith('.c'):
                files_to_ignore.add(ignore_path)

        # Normalize paths and remove files listed in [ignore] tag
        valid_files = []
        for file_path in all_scope_files:
            normalized_path = os.path.normpath(file_path)
            should_ignore = False

            for ignore_file in files_to_ignore:
                if os.path.normpath(ignore_file) == normalized_path:
                    should_ignore = True
                    break

            if not should_ignore:
                valid_files.append(normalized_path)

        self.all_files = valid_files

        # Separate the files into component-related and out-of-component types
        component_file_set = set()
        for comp_path in self.components:
            if comp_path.endswith('.c') and os.path.isfile(comp_path):
                component_file_set.add(os.path.normpath(comp_path))

        self.component_files = component_file_set
        self.out_of_component_files = set(self.all_files) - component_file_set

    def remove_comments_and_strings(self, content):
        """Remove comments & strings"""
        # Remove single-line comments
        content = re.sub(r'//.*', '', content)
        # Remove multiple-line comments
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        # Remove strings & chars
        content = re.sub(r'"([^"\\]|\\.)*"', '""', content)
        content = re.sub(r"'([^'\\]|\\.)*'", "''", content)
        return content

    def remove_macros(self, content):
        """Remove MACRO"""
        content = re.sub(r'#.*', '', content)
        return content

    def extract_function_calls_with_location(self, content, file_path):
        """Extract function calls with location"""
        lines = content.split('\n')
        function_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('

        calls_with_location = []

        for line_num, line in enumerate(lines, 1):
            matches = re.finditer(function_pattern, line)
            for match in matches:
                func_name = match.group(1)
                if func_name.lower() not in self.c_keywords:
                    calls_with_location.append((func_name, line_num))

        return calls_with_location

    def analyze_shared_resource_access(self, content, func_name, file_path):
        """Analyze shared resource access in function body"""
        if not self.share_resources:
            return

        # Remove comments and strings
        processed_content = self.remove_comments_and_strings(content)

        accessed_resources = set()
        access_details = []

        for resource in self.share_resources:
            # For each share resource, check if it is accessed in the function
            if self.check_resource_access_in_function(processed_content, resource, func_name):
                accessed_resources.add(resource)
                access_type = self.get_resource_access_type(processed_content, resource)
                access_details.append((resource, file_path, access_type))

        # Store the results
        self.function_resource_access[func_name].update(accessed_resources)
        self.resource_access_details[func_name].extend(access_details)

    def check_resource_access_in_function(self, content, resource, func_name):
        """Check the count of share resources used in the function（It may includes MACRO & inline function）"""
        direct_patterns = [
            rf'\b{re.escape(resource)}\b',      # Direct access to resource
            rf'->\s*{re.escape(resource)}\b',   # Access through pointer dereference
            rf'\.\s*{re.escape(resource)}\b',   # Access through struct member
            rf'\b{re.escape(resource)}\s*\[',   # Array access
        ]

        for pattern in direct_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True

    def get_resource_access_type(self, content, resource):
        """Get the access type(R/W) of a share resource"""
        # Find all patterns that match the resource
        patterns = [
            rf'\b{re.escape(resource)}\b',
            rf'->\s*{re.escape(resource)}\b',
            rf'\.\s*{re.escape(resource)}\b',
        ]

        write_indicators = 0
        read_indicators = 0

        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                access_type = self.determine_access_type(content, match.start())
                if access_type == "write":
                    write_indicators += 1
                else:
                    read_indicators += 1

        # Return "write" first if there are any write indicators
        if write_indicators > 0:
            return "write"
        elif read_indicators > 0:
            return "read"
        else:
            return "access"  # Accessed via MACRO or inline function, not sure the access type

    def determine_access_type(self, content, match_pos):
        """Determine the access type of a share resource based on its position in the content"""
        # Determine the access type according to the position of the match pattern
        start = max(0, match_pos - 100)
        end = min(len(content), match_pos + 100)

        before_match = content[start:match_pos].strip()
        after_match = content[match_pos:end].strip()

        # 尋找完整的語句來判斷存取類型
        # 向前尋找語句開始（到前一個分號或大括號）
        stmt_start = start
        for i in range(match_pos - 1, start - 1, -1):
            if content[i] in ';{}':
                stmt_start = i + 1
                break

        # 向後尋找語句結束（到下一個分號）
        stmt_end = end
        for i in range(match_pos, end):
            if content[i] == ';':
                stmt_end = i
                break

        statement = content[stmt_start:stmt_end].strip()

        # 檢查寫入模式
        write_patterns = [
            rf'[^=!<>]=(?!=)',  # 單一等號（排除==, !=, <=, >=）
            rf'\|=',            # |=
            rf'&=',             # &=
            rf'\+=',            # +=
            rf'-=',             # -=
            rf'\*=',            # *=
            rf'/=',             # /=
            rf'%=',             # %=
            rf'\^=',            # ^=
            rf'<<=',            # <<=
            rf'>>=',            # >>=
        ]

        # 找到資源在語句中的位置
        resource_pos_in_stmt = match_pos - stmt_start

        # 檢查資源是否在賦值操作符左邊
        for pattern in write_patterns:
            matches = list(re.finditer(pattern, statement))
            for match in matches:
                if match.start() > resource_pos_in_stmt:
                    # 賦值操作符在資源後面，表示資源被寫入
                    return "write"

        # 檢查是否是函數參數（通過指標傳遞可能被修改）
        if '(' in statement and ')' in statement:
            paren_start = statement.find('(')
            paren_end = statement.rfind(')')
            if paren_start < resource_pos_in_stmt < paren_end:
                # 資源在函數參數中，可能被修改
                return "read/write"

        # 預設為讀取
        return "read"

    def analyze_file_detailed(self, file_path):
        """Analyze single file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()

        # Keep original content for later use
        original_content = content

        # Preprocessing
        processed_content = self.remove_comments_and_strings(content)
        processed_content = self.remove_macros(processed_content)

        lines = processed_content.split('\n')
        file_functions = {}

        # 分析函數定義和呼叫
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            # 檢查函數模式
            function_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
            matches = re.finditer(function_pattern, line)

            for match in matches:
                func_name = match.group(1)
                if func_name.lower() in self.c_keywords:
                    continue

                # 判斷函數類型
                if line.endswith(';'):
                    # 可能是interface或callee
                    if self.is_inside_function_body(processed_content, line_num-1, lines):
                        # 這是函數呼叫
                        self.record_function_call(file_path, line_num, func_name)
                    else:
                        # 這是函數宣告
                        self.record_function_declaration(file_path, line_num, func_name)
                else:
                    # 可能是函數定義
                    if '{' in line or self.has_function_body_following(lines, line_num-1):
                        self.record_function_definition(file_path, line_num, func_name)
                        # 分析函數體內的呼叫
                        body = self.extract_function_body_from_lines(lines, line_num-1)
                        self.analyze_function_body_calls(file_path, func_name, body, line_num)

                        # 分析函數體內的共用資源存取
                        original_body = self.extract_function_body_from_original_content(original_content, func_name)
                        if original_body:
                            self.analyze_shared_resource_access(original_body, func_name, file_path)

        return file_functions

    def extract_function_body_from_original_content(self, content, func_name):
        """Extract function body from original content"""
        # Remove comments and strings
        processed_content = self.remove_comments_and_strings(content)

        # Find the function definition pattern
        # Consider both standard and multi-line function definitions
        patterns = [
            # Standard single line function definition:
            # return_type func_name(args) {
            #   ...
            # }
            rf'\b{re.escape(func_name)}\s*\([^{{;]*?\)\s*\{{',
            # Multi-line function definition:
            # return_type func_name(args)
            # {
            #   ...
            # }
            rf'\b{re.escape(func_name)}\s*\([^{{;]*?\)\s*[\r\n\s]*\{{',
        ]

        match = None
        for pattern in patterns:
            match = re.search(pattern, processed_content, re.DOTALL)
            if match:
                break

        if not match:
            return None

        # Find the start position of the function (the first '{' after the function name)
        func_start = match.start()
        brace_pos = processed_content.find('{', func_start)
        if brace_pos == -1:
            return None

        # Calculate the nesting level of braces from the first '{'
        brace_count = 1
        pos = brace_pos + 1

        while pos < len(processed_content) and brace_count > 0:
            char = processed_content[pos]
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
            pos += 1

        # Error handling: Ensure a matching closing brace was found
        if brace_count == 0:
            # Back to the function
            return processed_content[brace_pos + 1:pos - 1]
        else:
            # Back to the end of the file if no matching closing brace found
            return processed_content[brace_pos + 1:]

    def record_function_declaration(self, file_path, line_num, func_name):
        """Record function declaration"""
        self.interfaces.add(func_name)
        self.function_locations[func_name].append((file_path, line_num))

    def record_function_definition(self, file_path, line_num, func_name):
        """Record function definition"""
        self.callers.add(func_name)
        self.function_locations[func_name].append((file_path, line_num))

    def record_function_call(self, file_path, line_num, func_name):
        """Record function call"""
        self.callees.add(func_name)
        # 這裡需要知道是哪個函數在呼叫，暫時記錄位置
        # 實際的caller-callee關係在analyze_function_body_calls中處理

    def analyze_function_body_calls(self, file_path, caller_func, body, start_line):
        """Analyze function calls in the function body"""
        if not body:
            return

        body_lines = body.split('\n')
        function_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('

        for rel_line_num, line in enumerate(body_lines):
            matches = re.finditer(function_pattern, line)
            for match in matches:
                callee_func = match.group(1)
                if (callee_func.lower() not in self.c_keywords and
                    callee_func != caller_func):

                    # Record the caller-callee relationship
                    self.call_relationships[caller_func].append(callee_func)
                    self.callee_count[callee_func] += 1

                    # Record the call location
                    actual_line_num = start_line + rel_line_num
                    self.call_locations[(caller_func, callee_func)].append((file_path, actual_line_num))

    def is_inside_function_body(self, content, line_num, lines):
        """Check if the current line is inside a function body"""
        current_content = '\n'.join(lines[:line_num+1])
        open_braces = current_content.count('{')
        close_braces = current_content.count('}')
        return open_braces > close_braces

    def has_function_body_following(self, lines, line_num):
        """Check if the next few lines contain a function body"""
        for i in range(line_num, min(line_num + 5, len(lines))):
            if '{' in lines[i]:
                return True
        return False

    def extract_function_body_from_lines(self, lines, start_line):
        """Extract function body from lines starting from start_line"""
        body_lines = []
        brace_count = 0
        started = False

        for i in range(start_line, len(lines)):
            line = lines[i]
            body_lines.append(line)

            for char in line:
                if char == '{':
                    started = True
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if started and brace_count == 0:
                        return '\n'.join(body_lines)

        return '\n'.join(body_lines) if body_lines else ""

    def analyze_all_functions(self):
        """分析所有函數並分類"""
        # 先分析所有檔案以收集函數資訊
        for file_path in self.all_files:
            self.analyze_file_detailed(file_path)

        # 分類函數
        component_functions = set()
        out_of_component_functions = set()

        for func_name in (self.callers | self.interfaces | self.callees):
            func_locations = self.function_locations.get(func_name, [])
            is_in_component = any(file_path in self.component_files for file_path, _ in func_locations)

            if is_in_component:
                component_functions.add(func_name)
            else:
                out_of_component_functions.add(func_name)

        return component_functions, out_of_component_functions

    def calculate_interoperability(self, func_name, out_of_component_functions):
        """計算單一函數的Interoperability屬性"""
        interoperability = 0
        interop_details = []

        # 計算該函數被out of component呼叫的次數
        for caller, callees in self.call_relationships.items():
            # 檢查caller是否在out of component
            caller_locations = self.function_locations.get(caller, [])
            caller_in_out_component = any(file_path in self.out_of_component_files for file_path, _ in caller_locations)

            if caller_in_out_component and func_name in callees:
                count = callees.count(func_name)
                interoperability += count
                # 收集詳細資訊
                for file_path, line_num in self.call_locations.get((caller, func_name), []):
                    interop_details.append(f"Called by {caller} ({file_path})")

        # 計算該函數呼叫out of component函數的次數
        if func_name in self.call_relationships:
            for callee in self.call_relationships[func_name]:
                callee_locations = self.function_locations.get(callee, [])
                callee_in_out_component = any(file_path in self.out_of_component_files for file_path, _ in callee_locations)

                if callee_in_out_component:
                    count = self.call_relationships[func_name].count(callee)
                    interoperability += count
                    # 收集詳細資訊
                    for file_path, line_num in self.call_locations.get((func_name, callee), []):
                        interop_details.append(f"Calls {callee} ({file_path})")

        return interoperability, interop_details

    def calculate_interaction(self, func_name, component_functions):
        """計算單一函數的Interaction屬性"""
        interaction = 0
        interact_details = []

        # 計算該函數被同component其他函數呼叫的次數
        for caller, callees in self.call_relationships.items():
            # 檢查caller是否在component (且不是自己)
            caller_locations = self.function_locations.get(caller, [])
            caller_in_component = any(file_path in self.component_files for file_path, _ in caller_locations)

            if caller_in_component and caller != func_name and func_name in callees:
                count = callees.count(func_name)
                interaction += count
                # 收集詳細資訊
                for file_path, line_num in self.call_locations.get((caller, func_name), []):
                    interact_details.append(f"Called by {caller} ({file_path})")

        # 計算該函數呼叫同component其他函數的次數
        if func_name in self.call_relationships:
            for callee in self.call_relationships[func_name]:
                callee_locations = self.function_locations.get(callee, [])
                callee_in_component = any(file_path in self.component_files for file_path, _ in callee_locations)

                if callee_in_component and callee != func_name:
                    count = self.call_relationships[func_name].count(callee)
                    interaction += count
                    # 收集詳細資訊
                    for file_path, line_num in self.call_locations.get((func_name, callee), []):
                        interact_details.append(f"Calls {callee} ({file_path})")

        return interaction, interact_details

    def calculate_criticality(self, func_name):
        """計算單一函數的Criticality屬性"""
        # Criticality = 該函數存取的不同共用資源數量
        criticality = len(self.function_resource_access.get(func_name, set()))
        criticality_details = list(self.resource_access_details.get(func_name, []))

        return criticality, criticality_details

    def calculate_all_attributes(self):
        """Calculate all properties for each function in component"""
        results = {}

        # Analysis all functions and classify them
        component_functions, out_of_component_functions = self.analyze_all_functions()

        # Calculate properties for each function in SWC
        for func_name in component_functions:
            if func_name not in self.callers:  # Analysis caller only
                continue

            # Properties calculation
            interoperability, interop_details = self.calculate_interoperability(func_name, out_of_component_functions)
            interaction, interact_details = self.calculate_interaction(func_name, component_functions)
            criticality, criticality_details = self.calculate_criticality(func_name)

            results[func_name] = {
                'interoperability': interoperability,
                'interaction': interaction,
                'criticality': criticality,
                'interop_details': interop_details,
                'interact_details': interact_details,
                'criticality_details': criticality_details
            }

        return results

    # # 保持向後相容性的別名
    # def calculate_interoperability_and_interaction(self):
    #     """向後相容性方法，委派給新的calculate_all_attributes方法"""
    #     return self.calculate_all_attributes()

    def print_detailed_results(self, results):
        """Output detailed results"""
        print("=== Function call analysis for SW Component ===\n")

        print("Config File setting:")
        print(f"Component: {len(self.component_files)} files")
        for file_path in sorted(self.component_files):
            print(f"  - {file_path}")

        print(f"\nOut of Component: {len(self.out_of_component_files)} files")
        for file_path in sorted(self.out_of_component_files):
            print(f"  - {file_path}")

        print(f"\nIgnored: {len(self.ignores)} paths")
        for ignore_path in self.ignores:
            print(f"  - {ignore_path}")

        print(f"\nShared Resources: {len(self.share_resources)} resources")
        for resource in self.share_resources:
            print(f"  - {resource}")

        print("\n" + "="*60)
        print("Function analysis for SW Component:")
        print("="*60)

        # Output result by function name order
        for func_name in sorted(results.keys()):
            data = results[func_name]
            print(f"\n{func_name}")

            print(f"  Interoperability: {data['interoperability']}")
            # Debug info
            if data['interop_details']:
                for detail in data['interop_details']:
                    print(f"    - {detail}")

            print(f"  Interaction: {data['interaction']}")
            # Debug info
            if data['interact_details']:
                for detail in data['interact_details']:
                    print(f"    - {detail}")

            print(f"  Criticality: {data['criticality']}")
            # Debug info
            if data['criticality_details']:
                for resource, file_path, access_type in data['criticality_details']:
                    print(f"    - Accesses {resource} ({access_type}) in {file_path}")

    def print_legacy_results(self):
        """Output legacy results"""
        print("\n" + "="*60)
        print("Original Outputs:")
        print("="*60)

        print("\nInterfaces:")
        for interface in sorted(self.interfaces):
            print(f"  - {interface}")

        print("\nCallers:")
        for caller in sorted(self.callers):
            print(f"  - {caller}")

        print("\nCallees:")
        for callee in sorted(self.callees):
            print(f"  - {callee}")

        print("\nCall Relationships:")
        for caller in sorted(self.call_relationships.keys()):
            callees = self.call_relationships[caller]
            print(f"  {caller} -> {', '.join(set(callees))}")

        print("\nCaller treated as Callee counts:")
        caller_as_callee = {}
        for caller in self.callers:
            count = self.callee_count.get(caller, 0)
            caller_as_callee[caller] = count

        sorted_callers = sorted(caller_as_callee.items(), key=lambda x: x[1], reverse=True)

        for caller, count in sorted_callers:
            print(f"  {caller}: {count} times")

def main():
    parser = argparse.ArgumentParser(description='Analyze Interoperability, Interaction & Criticality for SW Component (C language)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-c', '--config', help='Path for config file, component, scope, ignore, share_resource settings should be included')

    args = parser.parse_args()

    analyzer = CFunctionAnalyzer()

    if not os.path.exists(args.config):
        print(f"Error: Config file '{args.config}' is not exist")
        return

    print(f"Reading config file: {args.config}")
    analyzer.parse_config_file(args.config)

    print("Collecting files to be analyzed...")
    analyzer.collect_files_to_analyze()

    if not analyzer.all_files:
        print("Warning: File is not found")
        return

    print(f"Total {len(analyzer.all_files)} files to be analyzed")
    print(f"Shared resources to monitor: {len(analyzer.share_resources)}")

    # Detail analysis
    print("Analyzing...")
    results = analyzer.calculate_all_attributes()

    # Output result
    analyzer.print_detailed_results(results)
    # analyzer.print_legacy_results()

if __name__ == "__main__":
    main()