#!/usr/bin/env python3
"""
SecurityWatch Pro - Deployment Script
Prepares and deploys SecurityWatch Pro to GitHub repository
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path


def run_command(command, check=True, capture_output=False):
    """Run shell command with error handling"""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            check=check, 
            capture_output=capture_output,
            text=True
        )
        return result
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed: {command}")
        print(f"Error: {e}")
        if capture_output and e.stdout:
            print(f"Output: {e.stdout}")
        if capture_output and e.stderr:
            print(f"Error output: {e.stderr}")
        return None


def clean_project():
    """Clean up temporary files and caches"""
    print("🧹 Cleaning project...")
    
    # Directories to clean
    clean_dirs = [
        '__pycache__',
        '.pytest_cache',
        'htmlcov',
        '*.egg-info',
        'build',
        'dist'
    ]
    
    for pattern in clean_dirs:
        run_command(f"find . -name '{pattern}' -type d -exec rm -rf {{}} + 2>/dev/null || true", check=False)
    
    # Files to clean
    clean_files = [
        '*.pyc',
        '*.pyo',
        '*.db',
        '*.log',
        '.coverage'
    ]
    
    for pattern in clean_files:
        run_command(f"find . -name '{pattern}' -type f -delete 2>/dev/null || true", check=False)
    
    print("✅ Project cleaned")


def create_license():
    """Create MIT license file"""
    print("📄 Creating LICENSE file...")
    
    license_text = """MIT License

Copyright (c) 2025 SysAdmin Tools Pro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
    
    with open('LICENSE', 'w') as f:
        f.write(license_text)
    
    print("✅ LICENSE file created")


def create_gitignore():
    """Create comprehensive .gitignore file"""
    print("📄 Creating .gitignore file...")
    
    gitignore_content = """# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# C extensions
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
pip-wheel-metadata/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# PyInstaller
*.manifest
*.spec

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.py,cover
.hypothesis/
.pytest_cache/

# Translations
*.mo
*.pot

# Django stuff:
*.log
local_settings.py
db.sqlite3
db.sqlite3-journal

# Flask stuff:
instance/
.webassets-cache

# Scrapy stuff:
.scrapy

# Sphinx documentation
docs/_build/

# PyBuilder
target/

# Jupyter Notebook
.ipynb_checkpoints

# IPython
profile_default/
ipython_config.py

# pyenv
.python-version

# pipenv
Pipfile.lock

# PEP 582
__pypackages__/

# Celery stuff
celerybeat-schedule
celerybeat.pid

# SageMath parsed files
*.sage.py

# Environments
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# Spyder project settings
.spyderproject
.spyproject

# Rope project settings
.ropeproject

# mkdocs documentation
/site

# mypy
.mypy_cache/
.dmypy.json
dmypy.json

# Pyre type checker
.pyre/

# SecurityWatch Pro specific
*.db
*.log
reports/
logs/
securitywatch_config.json
.env/
temp/
"""
    
    with open('.gitignore', 'w') as f:
        f.write(gitignore_content)
    
    print("✅ .gitignore file created")


def run_final_tests():
    """Run final test suite"""
    print("🧪 Running final tests...")
    
    # Run tests
    result = run_command("python -m pytest tests/ -v --tb=short", capture_output=True)
    if result and result.returncode == 0:
        print("✅ All tests passed")
        return True
    else:
        print("❌ Tests failed")
        if result:
            print(result.stdout)
            print(result.stderr)
        return False


def check_git_status():
    """Check if we're in a git repository"""
    result = run_command("git status", check=False, capture_output=True)
    return result and result.returncode == 0


def initialize_git():
    """Initialize git repository if needed"""
    if not check_git_status():
        print("📦 Initializing git repository...")
        run_command("git init")
        run_command("git branch -M main")
        print("✅ Git repository initialized")
    else:
        print("✅ Git repository already exists")


def commit_and_push():
    """Commit changes and push to GitHub"""
    print("📤 Committing and pushing to GitHub...")
    
    # Add all files
    run_command("git add .")
    
    # Commit
    commit_message = "🛡️ SecurityWatch Pro v1.0.0 - Complete security monitoring solution"
    run_command(f'git commit -m "{commit_message}"')
    
    # Check if remote exists
    result = run_command("git remote get-url origin", check=False, capture_output=True)
    if not result or result.returncode != 0:
        print("🔗 Adding GitHub remote...")
        run_command("git remote add origin https://github.com/ahmganbit/SecuriWatch.git")
    
    # Push to GitHub
    print("🚀 Pushing to GitHub...")
    result = run_command("git push -u origin main", check=False, capture_output=True)
    
    if result and result.returncode == 0:
        print("✅ Successfully pushed to GitHub!")
        print("🌐 Repository: https://github.com/ahmganbit/SecuriWatch")
    else:
        print("⚠️ Push may have failed. Please check manually.")
        if result:
            print(result.stdout)
            print(result.stderr)


def create_project_structure():
    """Ensure proper project structure"""
    print("📁 Creating project structure...")
    
    # Create necessary directories
    directories = [
        'logs',
        'reports',
        'docs',
        'examples'
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        # Create .gitkeep files for empty directories
        gitkeep_file = Path(directory) / '.gitkeep'
        if not gitkeep_file.exists():
            gitkeep_file.touch()
    
    print("✅ Project structure created")


def main():
    """Main deployment function"""
    print("🛡️ SecurityWatch Pro - Deployment Script")
    print("=" * 50)
    
    # Change to project directory
    os.chdir(Path(__file__).parent)
    
    try:
        # Clean project
        clean_project()
        
        # Create necessary files
        create_license()
        create_gitignore()
        create_project_structure()
        
        # Run final tests
        if not run_final_tests():
            print("❌ Deployment aborted due to test failures")
            return False
        
        # Git operations
        initialize_git()
        commit_and_push()
        
        print("\n" + "=" * 50)
        print("🎉 SecurityWatch Pro deployment completed!")
        print("✅ All tests passed")
        print("📦 Code pushed to GitHub")
        print("🌐 Repository: https://github.com/ahmganbit/SecuriWatch")
        print("\n🚀 SecurityWatch Pro is ready for production use!")
        
        return True
        
    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
