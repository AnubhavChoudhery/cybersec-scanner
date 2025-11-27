"""Setup configuration for cybersec-scanner package."""

from setuptools import setup, find_packages
from pathlib import Path

# Read version from __version__.py
version = {}
with open("cybersec_scanner/__version__.py") as f:
    exec(f.read(), version)

# Read long description from README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip()
        for line in requirements_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="cybersec-scanner",
    version=version["__version__"],
    author=version["__author__"],
    author_email="cybersec-team@example.com",  # Update with your email
    description=version["__description__"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AnubhavChoudhery/cybersec-scanner",
    project_urls={
        "Bug Reports": "https://github.com/AnubhavChoudhery/cybersec-scanner/issues",
        "Source": "https://github.com/AnubhavChoudhery/cybersec-scanner",
        "Documentation": "https://github.com/AnubhavChoudhery/cybersec-scanner/blob/main/README.md",
    },
    packages=[
        "cybersec_scanner",
        "cybersec_scanner.cli",
        "cybersec_scanner.database",
        "cybersec_scanner.rag",
        "cybersec_scanner.scanners",
    ],
    package_data={
        "cybersec_scanner": [
            "database/schema.sql",
            "knowledge_base/*.json",
        ],
    },
    include_package_data=True,
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "vector": [
            "sentence-transformers>=2.0.0",
            "hnswlib>=0.7.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cybersec-scanner=cybersec_scanner.cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.11",
    keywords="security scanner vulnerability audit rag llm cybersecurity",
    license=version["__license__"],
)
