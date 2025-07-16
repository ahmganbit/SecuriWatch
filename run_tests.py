#!/usr/bin/env python3
"""
SecurityWatch Pro - Test Runner
Runs all tests and generates coverage reports
"""

import sys
import subprocess
import os
from pathlib import Path

def run_tests():
    """Run all tests with coverage"""
    project_root = Path(__file__).parent
    os.chdir(project_root)
    
    print("🧪 Running SecurityWatch Pro Tests")
    print("=" * 50)
    
    # Install dependencies
    print("📦 Installing dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                      check=True, capture_output=True)
        print("✅ Dependencies installed")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False
    
    # Install package in development mode
    print("📦 Installing SecurityWatch Pro in development mode...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-e", "."], 
                      check=True, capture_output=True)
        print("✅ SecurityWatch Pro installed")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install SecurityWatch Pro: {e}")
        return False
    
    # Run tests with coverage
    print("\n🔍 Running tests with coverage...")
    try:
        result = subprocess.run([
            sys.executable, "-m", "pytest", 
            "tests/", 
            "-v", 
            "--cov=securitywatch", 
            "--cov-report=html", 
            "--cov-report=term-missing"
        ], check=True)
        
        print("✅ All tests passed!")
        print("📊 Coverage report generated in htmlcov/")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Tests failed with exit code {e.returncode}")
        return False
    
    except FileNotFoundError:
        print("❌ pytest not found. Installing...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "pytest", "pytest-cov"], 
                          check=True)
            print("✅ pytest installed, rerunning tests...")
            return run_tests()
        except subprocess.CalledProcessError:
            print("❌ Failed to install pytest")
            return False

def run_linting():
    """Run code linting"""
    print("\n📝 Running code linting...")
    
    try:
        # Run flake8
        subprocess.run([sys.executable, "-m", "flake8", "securitywatch/", "tests/"], check=True)
        print("✅ Linting passed")
        return True
    except subprocess.CalledProcessError:
        print("❌ Linting failed")
        return False
    except FileNotFoundError:
        print("⚠️  flake8 not found, skipping linting")
        return True

def run_security_checks():
    """Run basic security checks"""
    print("\n🔒 Running security checks...")
    
    # Check for common security issues
    security_checks = [
        "grep -r 'password.*=' securitywatch/ || true",
        "grep -r 'secret.*=' securitywatch/ || true", 
        "grep -r 'api_key.*=' securitywatch/ || true"
    ]
    
    for check in security_checks:
        print(f"Running: {check}")
        os.system(check)

def test_cli():
    """Test CLI functionality"""
    print("\n🖥️  Testing CLI functionality...")
    
    try:
        # Test CLI help
        result = subprocess.run([sys.executable, "securitywatch_cli.py", "--help"], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ CLI help works")
        else:
            print("❌ CLI help failed")
            return False
        
        # Test CLI status (should work even without monitoring)
        result = subprocess.run([sys.executable, "securitywatch_cli.py", "status"], 
                               capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ CLI status works")
        else:
            print("⚠️  CLI status returned non-zero (expected if no logs found)")
        
        return True
        
    except Exception as e:
        print(f"❌ CLI test failed: {e}")
        return False

def main():
    """Main test runner"""
    print("🛡️ SecurityWatch Pro - Comprehensive Test Suite")
    print("=" * 60)
    
    success = True
    
    # Run unit tests
    if not run_tests():
        success = False
    
    # Run linting
    if not run_linting():
        success = False
    
    # Run security checks
    run_security_checks()
    
    # Test CLI
    if not test_cli():
        success = False
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 All tests completed successfully!")
        print("✅ SecurityWatch Pro is ready for deployment")
    else:
        print("❌ Some tests failed. Please review the output above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
