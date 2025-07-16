#!/usr/bin/env python3
"""
SecurityWatch Pro - Setup Script
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    with open(requirements_file, 'r') as f:
        requirements = [
            line.strip() for line in f 
            if line.strip() and not line.startswith('#') and not line.startswith('-')
        ]

setup(
    name="securitywatch-pro",
    version="1.0.0",
    author="SysAdmin Tools Pro",
    author_email="support@sysadmintoolspro.com",
    description="Professional security monitoring with intelligent pattern recognition and automated threat detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ahmganbit/SecuriWatch",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
        ],
        "advanced": [
            "psutil>=5.9.0",
            "watchdog>=2.1.0",
            "geoip2>=4.6.0",
            "requests>=2.28.0",
        ],
        "ml": [
            "scikit-learn>=1.1.0",
            "numpy>=1.21.0",
            "pandas>=1.4.0",
        ],
        "web": [
            "flask>=2.2.0",
            "flask-login>=0.6.0",
            "flask-wtf>=1.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "securitywatch=securitywatch_cli:main",
            "securitywatch-pro=securitywatch_cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "securitywatch": [
            "templates/*.html",
            "static/*.css",
            "static/*.js",
        ],
    },
    keywords=[
        "security", "monitoring", "intrusion-detection", "log-analysis", 
        "threat-detection", "cybersecurity", "sysadmin", "network-security",
        "brute-force", "attack-detection", "security-audit", "compliance"
    ],
    project_urls={
        "Bug Reports": "https://github.com/ahmganbit/SecuriWatch/issues",
        "Source": "https://github.com/ahmganbit/SecuriWatch",
        "Documentation": "https://github.com/ahmganbit/SecuriWatch/wiki",
    },
)
