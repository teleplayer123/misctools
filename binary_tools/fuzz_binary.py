#!/usr/bin/env python3
"""
Binary Fuzzer - Fuzz test inputs against a command-line binary executable.
Supports: basic fuzzing, pattern-based fuzzing, mutation-based fuzzing, and result tracking.
"""

import subprocess
import sys
import argparse
import random
import string
import re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Callable
from collections import defaultdict


@dataclass
class FuzzResult:
    """Result from running a single fuzz input against the binary."""
    input_value: str
    exit_code: int
    stdout: str
    stderr: str
    timing: float = 0.0
    error: Optional[str] = None


class BinaryFuzzer:
    """Fuzzer for command-line binary executables with a single argument."""
    
    def __init__(self, binary_path: str, timeout: int = 10):
        """
        Initialize the fuzzer.
        
        Args:
            binary_path: Path to the binary executable
            timeout: Timeout in seconds for each fuzz test
        """
        self.binary_path = Path(binary_path).resolve()
        self.timeout = timeout
        self.results: List[FuzzResult] = []
        self.failed_tests: List[FuzzResult] = []
        self.successful_tests: List[FuzzResult] = []
        self.stable_outputs: dict = defaultdict(list)
        
        # Validate binary exists and is executable
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        if not self.binary_path.stat().st_mode & 0o111:
            raise PermissionError(f"Binary is not executable: {binary_path}")
    
    def run_test(self, input_value: str) -> FuzzResult:
        """Run a single fuzz test against the binary."""
        import time
        
        try:
            start_time = time.time()
            result = subprocess.run(
                [str(self.binary_path), input_value],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            timing = time.time() - start_time
            
            return FuzzResult(
                input_value=input_value,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                timing=timing
            )
        except subprocess.TimeoutExpired:
            return FuzzResult(
                input_value=input_value,
                exit_code=-1,
                stdout="",
                stderr="Timeout",
                error=f"Timed out after {self.timeout}s"
            )
        except Exception as e:
            return FuzzResult(
                input_value=input_value,
                exit_code=-1,
                stdout="",
                stderr="",
                error=str(e)
            )
    
    def generate_basic_inputs(self, count: int) -> List[str]:
        """Generate basic fuzz inputs: empty, single chars, short strings."""
        inputs = []
        
        # Empty input
        inputs.append("")
        
        # Single characters (printable ASCII)
        for c in string.printable[:50]:
            inputs.append(c)
        
        # Short strings (1-5 chars)
        for length in range(1, 6):
            for _ in range(3):
                inputs.append("".join(random.choices(string.printable[:50], k=length)))
        
        return inputs
    
    def generate_pattern_inputs(self, patterns: List[str], count: int) -> List[str]:
        """Generate inputs based on specific patterns."""
        inputs = []
        
        for pattern in patterns:
            for _ in range(count):
                # Randomly fill the pattern
                filled = pattern
                for char in pattern:
                    if char == "{":
                        filled += random.choices(string.printable[:50], k=random.randint(1, 5))[0]
                    elif char == "}":
                        filled += random.choices(string.printable[:50], k=random.randint(1, 5))[0]
                inputs.append(filled)
        
        return inputs
    
    def generate_mutation_inputs(self, base_input: str, mutations: int) -> List[str]:
        """Generate mutated versions of a base input."""
        inputs = [base_input]
        
        def mutate(s):
            """Apply a random mutation to a string."""
            if not s:
                return s
            mutation_type = random.choice(["insert", "delete", "substitute", "reverse", "nullify"])
            
            if mutation_type == "nullify":
                return ""
            elif mutation_type == "reverse":
                return s[::-1]
            elif mutation_type == "delete":
                return s[:-1] if len(s) > 0 else s
            elif mutation_type == "insert":
                pos = random.randint(0, len(s))
                insert = random.choices(string.printable[:50], k=1)[0]
                return s[:pos] + insert + s[pos:]
            elif mutation_type == "substitute":
                pos = random.randint(0, len(s) - 1)
                return s[:pos] + random.choices(string.printable[:50], k=1)[0] + s[pos+1:]
            
            return s
        
        for _ in range(mutations):
            mutated = mutate(random.choice(inputs))
            if mutated not in inputs:
                inputs.append(mutated)
        
        return inputs
    
    def generate_path_inputs(self, count: int) -> List[str]:
        """Generate path-like inputs."""
        inputs = []
        dirs = ["/", "./", "../", "/tmp/", "/home/", "/usr/", "/bin/", "/etc/"]
        files = ["test", "file", "data", "config", "input", "output", "readme", "test.txt"]
        
        for _ in range(count):
            parts = random.choices(dirs + files, k=random.randint(1, 5))
            inputs.append("/".join(parts))
        
        return inputs
    
    def generate_url_inputs(self, count: int) -> List[str]:
        """Generate URL-like inputs."""
        inputs = []
        schemes = ["http://", "https://", "ftp://", "file://"]
        domains = ["example.com", "test.org", "localhost", "127.0.0.1", "google.com"]
        paths = ["/", "/index.html", "/api", "/path/to/resource", "/v1/users"]
        query = ["?id=1", "?name=test", "?file=data.txt"]
        
        for _ in range(count):
            scheme = random.choice(schemes)
            host = random.choice(domains)
            path = random.choice(paths)
            query_part = random.choices(query, k=1)[0]
            inputs.append(f"{scheme}{host}{path}{query_part}")
        
        return inputs
    
    def generate_special_inputs(self, count: int) -> List[str]:
        """Generate special/edge-case inputs."""
        inputs = []
        
        # Null bytes
        inputs.append("\x00")
        
        # Newlines
        inputs.append("\n")
        inputs.append("\r\n")
        
        # Tabs
        inputs.append("\t")
        
        # Unicode
        inputs.append("🔐")
        inputs.append("日本語")
        inputs.append("café")
        
        # Control characters
        for i in range(32, 127):
            inputs.append(chr(i))
        
        return inputs
    
    def run_basic_fuzz(self, count: int = 100) -> None:
        """Run basic fuzzing with random inputs."""
        print(f"Running basic fuzz (count={count})...")
        inputs = self.generate_basic_inputs(count)
        
        for i, input_val in enumerate(inputs):
            result = self.run_test(input_val)
            self.results.append(result)
            if result.error or result.exit_code != 0:
                self.failed_tests.append(result)
            else:
                self.successful_tests.append(result)
            
            if (i + 1) % 10 == 0:
                print(f"  Processed {i + 1}/{count} inputs")
        
        print(f"Basic fuzz complete: {len(self.successful_tests)} passed, {len(self.failed_tests)} failed")
    
    def run_pattern_fuzz(self, patterns: List[str], count: int = 50) -> None:
        """Run fuzzing with pattern-based inputs."""
        print(f"Running pattern fuzz (patterns={len(patterns)}, count={count})...")
        inputs = self.generate_pattern_inputs(patterns, count)
        
        for i, input_val in enumerate(inputs):
            result = self.run_test(input_val)
            self.results.append(result)
            if result.error or result.exit_code != 0:
                self.failed_tests.append(result)
            else:
                self.successful_tests.append(result)
            
            if (i + 1) % 10 == 0:
                print(f"  Processed {i + 1}/{count} inputs")
        
        print(f"Pattern fuzz complete: {len(self.successful_tests)} passed, {len(self.failed_tests)} failed")
    
    def run_path_fuzz(self, count: int = 50) -> None:
        """Run fuzzing with path-like inputs."""
        print(f"Running path fuzz (count={count})...")
        inputs = self.generate_path_inputs(count)
        
        for i, input_val in enumerate(inputs):
            result = self.run_test(input_val)
            self.results.append(result)
            if result.error or result.exit_code != 0:
                self.failed_tests.append(result)
            else:
                self.successful_tests.append(result)
            
            if (i + 1) % 10 == 0:
                print(f"  Processed {i + 1}/{count} inputs")
        
        print(f"Path fuzz complete: {len(self.successful_tests)} passed, {len(self.failed_tests)} failed")
    
    def run_url_fuzz(self, count: int = 50) -> None:
        """Run fuzzing with URL-like inputs."""
        print(f"Running URL fuzz (count={count})...")
        inputs = self.generate_url_inputs(count)
        
        for i, input_val in enumerate(inputs):
            result = self.run_test(input_val)
            self.results.append(result)
            if result.error or result.exit_code != 0:
                self.failed_tests.append(result)
            else:
                self.successful_tests.append(result)
            
            if (i + 1) % 10 == 0:
                print(f"  Processed {i + 1}/{count} inputs")
        
        print(f"URL fuzz complete: {len(self.successful_tests)} passed, {len(self.failed_tests)} failed")
    
    def run_special_fuzz(self, count: int = 50) -> None:
        """Run fuzzing with special/edge-case inputs."""
        print(f"Running special fuzz (count={count})...")
        inputs = self.generate_special_inputs(count)
        
        for i, input_val in enumerate(inputs):
            result = self.run_test(input_val)
            self.results.append(result)
            if result.error or result.exit_code != 0:
                self.failed_tests.append(result)
            else:
                self.successful_tests.append(result)
            
            if (i + 1) % 10 == 0:
                print(f"  Processed {i + 1}/{count} inputs")
        
        print(f"Special fuzz complete: {len(self.successful_tests)} passed, {len(self.failed_tests)} failed")
    
    def run_mutate_fuzz(self, base_input: str, mutations: int = 50) -> None:
        """Run fuzzing with mutated versions of a base input."""
        print(f"Running mutation fuzz (base='{base_input}', mutations={mutations})...")
        inputs = self.generate_mutation_inputs(base_input, mutations)
        
        for i, input_val in enumerate(inputs):
            result = self.run_test(input_val)
            self.results.append(result)
            if result.error or result.exit_code != 0:
                self.failed_tests.append(result)
            else:
                self.successful_tests.append(result)
            
            if (i + 1) % 10 == 0:
                print(f"  Processed {i + 1}/{count} inputs")
        
        print(f"Mutation fuzz complete: {len(self.successful_tests)} passed, {len(self.failed_tests)} failed")
    
    def run_all_fuzzes(self) -> None:
        """Run all fuzz types."""
        print("Starting comprehensive fuzzing suite...")
        print("=" * 60)
        
        self.run_basic_fuzz(count=100)
        self.run_pattern_fuzz(patterns=["{...}", "{...}{...}", "{...}{...}{...}"], count=50)
        self.run_path_fuzz(count=50)
        self.run_url_fuzz(count=50)
        self.run_special_fuzz(count=50)
        self.run_mutate_fuzz(base_input="test", mutations=50)
        
        print("=" * 60)
        print(f"Total tests: {len(self.results)}")
        print(f"Successful: {len(self.successful_tests)}")
        print(f"Failed: {len(self.failed_tests)}")


def main():
    parser = argparse.ArgumentParser(description="Binary Fuzzer - Test inputs against a CLI binary")
    
    parser.add_argument("binary", type=str, help="Path to the binary executable")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout per test (default: 10)")
    parser.add_argument("--output", type=str, default=None, help="Output file for results (JSON)")
    parser.add_argument("--basic", action="store_true", help="Run basic fuzz only")
    parser.add_argument("--pattern", action="store_true", help="Run pattern fuzz only")
    parser.add_argument("--path", action="store_true", help="Run path fuzz only")
    parser.add_argument("--url", action="store_true", help="Run URL fuzz only")
    parser.add_argument("--special", action="store_true", help="Run special fuzz only")
    parser.add_argument("--mutate", action="store_true", help="Run mutation fuzz only")
    parser.add_argument("--mutate-base", type=str, default="test", help="Base input for mutation fuzz")
    parser.add_argument("--mutate-count", type=int, default=50, help="Number of mutations")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    
    args = parser.parse_args()
    
    try:
        fuzzer = BinaryFuzzer(args.binary, timeout=args.timeout)
        
        if args.quiet:
            fuzzer.run_all_fuzzs()
        else:
            if args.basic:
                fuzzer.run_basic_fuzz(count=100)
            elif args.pattern:
                fuzzer.run_pattern_fuzz(patterns=["{...}", "{...}{...}", "{...}{...}{...}"], count=50)
            elif args.path:
                fuzzer.run_path_fuzz(count=50)
            elif args.url:
                fuzzer.run_url_fuzz(count=50)
            elif args.special:
                fuzzer.run_special_fuzz(count=50)
            elif args.mutate:
                fuzzer.run_mutate_fuzz(base_input=args.mutate_base, mutations=args.mutate_count)
            else:
                fuzzer.run_all_fuzzes()
        
        # Print summary
        print("\n" + "=" * 60)
        print("FUZZING SUMMARY")
        print("=" * 60)
        print(f"Total tests: {len(fuzzer.results)}")
        print(f"Successful: {len(fuzzer.successful_tests)}")
        print(f"Failed: {len(fuzzer.failed_tests)}")
        
        # Show some failed test examples
        if fuzzer.failed_tests:
            print("\nSample failed test inputs:")
            for result in fuzzer.failed_tests[:5]:
                print(f"  Input: {repr(result.input_value)}")
                print(f"    Exit code: {result.exit_code}")
                if result.error:
                    print(f"    Error: {result.error}")
                if result.stdout:
                    print(f"    Stdout: {result.stdout.strip()[:200]}")
                if result.stderr:
                    print(f"    Stderr: {result.stderr.strip()[:200]}")
        
        # Save results to file if requested
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump({
                    "binary": str(fuzzer.binary_path),
                    "total": len(fuzzer.results),
                    "successful": len(fuzzer.successful_tests),
                    "failed": len(fuzzer.failed_tests),
                    "results": [
                        {
                            "input": r.input_value,
                            "exit_code": r.exit_code,
                            "stdout": r.stdout,
                            "stderr": r.stderr,
                            "error": r.error,
                            "timing": r.timing
                        }
                        for r in fuzzer.results
                    ]
                }, f, indent=2)
            print(f"\nResults saved to {args.output}")
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
