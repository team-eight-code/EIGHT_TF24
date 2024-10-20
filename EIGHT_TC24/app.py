import os
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
import traceback
from transformers import pipeline
import re
import sys
import ast
import autopep8
import difflib
import base64
from github import Github
import time
import subprocess
import tempfile

app = Flask(__name__)
CORS(app)

# Hugging Face API token (replace with your actual token)
HF_API_TOKEN = "HF_API_TOKEN"

# GitHub API token (replace with your actual token)
GITHUB_API_TOKEN = "GITHUB_API_TOKEN"

# Initialize the classification pipeline
try:
    classifier = pipeline("text-classification", model="distilbert-base-uncased")
except Exception as e:
    print(f"Error initializing classifier: {str(e)}")
    print(traceback.format_exc())
    sys.exit(1)

# Vulnerability patterns with descriptions, risk levels, and remediation suggestions
VULNERABILITY_PATTERNS = {
    'sql_injection': {
        'pattern': r'SELECT.*FROM.*WHERE',
        'description': 'SQL Injection vulnerability detected. This could allow an attacker to manipulate your database queries.',
        'risk_level': 'High',
        'severity_score': 8,
        'remediation': 'Use parameterized queries or prepared statements instead of concatenating user input directly into SQL queries.',
        'resource': 'https://owasp.org/www-community/attacks/SQL_Injection'
    },
    'xss': {
        'pattern': r'<script>.*</script>',
        'description': 'Cross-Site Scripting (XSS) vulnerability detected. This could allow an attacker to inject malicious scripts into your web pages.',
        'risk_level': 'High',
        'severity_score': 7,
        'remediation': 'Sanitize and validate all user input before rendering it in HTML. Use content security policies and output encoding.',
        'resource': 'https://owasp.org/www-community/attacks/xss/'
    },
    'command_injection': {
        'pattern': r'exec\(|system\(|shell_exec\(',
        'description': 'Command Injection vulnerability detected. This could allow an attacker to execute arbitrary commands on your system.',
        'risk_level': 'Critical',
        'severity_score': 9,
        'remediation': 'Avoid using user input in system commands. If necessary, use a whitelist of allowed commands and sanitize user input.',
        'resource': 'https://owasp.org/www-community/attacks/Command_Injection'
    },
    'path_traversal': {
        'pattern': r'\.\./',
        'description': 'Path Traversal vulnerability detected. This could allow an attacker to access files outside the intended directory.',
        'risk_level': 'Medium',
        'severity_score': 6,
        'remediation': 'Validate and sanitize file paths. Use a whitelist of allowed directories and files.',
        'resource': 'https://owasp.org/www-community/attacks/Path_Traversal'
    },
}

def rule_based_analysis(code):
    vulnerabilities = []
    for vuln_type, vuln_info in VULNERABILITY_PATTERNS.items():
        matches = re.finditer(vuln_info['pattern'], code, re.IGNORECASE)
        for match in matches:
            vulnerabilities.append({
                'type': vuln_type,
                'description': vuln_info['description'],
                'risk_level': vuln_info['risk_level'],
                'severity_score': vuln_info['severity_score'],
                'remediation': vuln_info['remediation'],
                'resource': vuln_info['resource'],
                'line_number': code[:match.start()].count('\n') + 1,
                'code_snippet': code[max(0, match.start() - 50):min(len(code), match.end() + 50)]
            })
    return vulnerabilities

def detect_language_by_keywords(code: str) -> str:
    # Dictionary of languages and their unique keywords or patterns
    language_patterns = {
        "Python": [r"\bdef\b", r"\bprint\b", r"\bimport\b", r":\s*$", r"\bclass\b"],
        "JavaScript": [r"\bfunction\b", r"\bconsole\.log\b", r"\bvar\b", r"\blet\b", r"\bconst\b"],
        "C++": [r"#include", r"\bstd::\b", r"\bcout\b", r"\bcin\b", r"\bint main\b"],
        "C": [r"#include", r"\bprintf\b", r"\bscanf\b", r"\bint main\b"],
        "HTML": [r"<!DOCTYPE html>", r"<html>", r"<head>", r"<body>", r"<title>"],
        "SQL": [r"\bSELECT\b", r"\bFROM\b", r"\bWHERE\b", r"\bINSERT\b", r"\bUPDATE\b", r"\bDELETE\b"],
        "Bash": [r"#!/bin/bash", r"echo", r"fi", r"if \[", r"else", r"for"],
        "Rust": [r"\bfn\b", r"\blet mut\b", r"\bprintln!\b", r"\bextern crate\b", r"\bimpl\b"]
    }

    detected_language = "Language not detected."
    for language, patterns in language_patterns.items():
            for pattern in patterns:
                if re.search(pattern, code):
                    detected_language = language
                    break
            if detected_language != "Language not detected.":
                break
    print(f"Detected language: {detected_language}")  # Debugging line
    return detected_language

def correct_vulnerabilities(code, vulnerabilities, language):
    try:
        if language.lower() == 'python':
            tree = ast.parse(code)
            corrector = VulnerabilityCorrector(vulnerabilities)
            corrected_tree = corrector.visit(tree)
            return ast.unparse(corrected_tree)
        elif language.lower() == 'javascript':
            # Implement JavaScript-specific corrections
            return code  # Placeholder
        elif language.lower() == 'cpp':
            # Implement C++-specific corrections
            return code  # Placeholder
        else:
            return code
    except Exception as e:
        app.logger.error(f"Error correcting vulnerabilities: {str(e)}")
        return code

class VulnerabilityCorrector(ast.NodeTransformer):
    def __init__(self, vulnerabilities):
        self.vulnerabilities = vulnerabilities

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id in ['exec', 'eval']:
                # Replace exec() and eval() with safer alternatives
                return ast.parse('print("Unsafe function call removed")').body[0]
        return node

    def visit_Str(self, node):
        # Check for potential XSS in string literals
        if '<script>' in node.s:
            return ast.Str(s=node.s.replace('<script>', '').replace('</script>', ''))
        return node

    # Add more visit methods for other vulnerability types

def run_formatter(formatter, code):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as tmp_file:
            tmp_file.write(code.encode('utf-8'))
            tmp_file.flush()
            subprocess.run([formatter, tmp_file.name], check=True)
            with open(tmp_file.name, 'r') as f:
                formatted_code = f.read()
        return formatted_code
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Formatter failed: {e}")
        return code

def correct_code(code, vulnerabilities, language):
    try:
        # Step 1: Correct vulnerabilities
        code = correct_vulnerabilities(code, vulnerabilities, language)

        # Step 2: Format the code based on the language
        if language.lower() == 'python':
            code = autopep8.fix_code(code)
        elif language.lower() == 'javascript':
            code = run_formatter('prettier', code)
        elif language.lower() == 'cpp':
            code = run_formatter('clang-format', code)
        # Add more languages/formats as needed

        return code
    except Exception as e:
        app.logger.error(f"Error correcting code: {str(e)}")
        return code

def generate_diff(original, corrected):
    d = difflib.unified_diff(original.splitlines(), corrected.splitlines(), lineterm='', n=3)
    return '\n'.join(d)

@app.route('/analyze_code', methods=['POST'])
def analyze_code():
    try:
        data = request.json
        code = data.get('code', '')

        if not code:
            return jsonify({"error": "Please provide code to analyze."}), 400

        # Detect language based on code
        detected_language = detect_language_by_keywords(code)

        # Rule-based analysis
        rule_based_result = rule_based_analysis(code)

        # Correct the code
        corrected_code = correct_code(code, rule_based_result, detected_language)

        # ML-based analysis
        ml_result = classifier(corrected_code)[0]

        # Determine overall risk
        risk_levels = [vuln['risk_level'] for vuln in rule_based_result]
        if 'Critical' in risk_levels:
            overall_risk = 'Critical'
        elif 'High' in risk_levels or ml_result['score'] > 0.7:
            overall_risk = 'High'
        elif 'Medium' in risk_levels or ml_result['score'] > 0.4:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'

        # Generate a diff between original and corrected code
        diff = generate_diff(code, corrected_code)

        # Sort vulnerabilities by severity score
        rule_based_result.sort(key=lambda x: x['severity_score'], reverse=True)

        # Combine results
        analysis = {
            "ml_analysis": ml_result,
            "rule_based_analysis": rule_based_result,
            "overall_risk": overall_risk,
            "original_code": code,
            "corrected_code": corrected_code,
            "diff": diff,
            "language": detected_language
        }
        print(f"Analysis response: {analysis}")  # Debugging line
        return jsonify({"analysis": analysis})
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({"error": f"Unexpected error: {str(e)}", "traceback": traceback.format_exc()}), 500

if __name__ == '__main__':
    app.run(debug=True)
