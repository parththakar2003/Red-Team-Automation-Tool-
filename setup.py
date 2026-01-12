"""
Setup script for Red Team Automation Framework
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="redteam-automation-framework",
    version="1.0.0",
    author="Security Assessment Team",
    author_email="security@example.com",
    description="Professional Red Team Automation Framework for authorized security testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/parththakar2003/Red-Team-Automation-Tool-",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "redteam=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["config.yaml"],
    },
)
