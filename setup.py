from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="sshclaude",
    version="0.1.0",
    author="Sunil Mallya",
    author_email="mallya16 @ gmail",
    description="Secure Claude Terminal in Your Browser",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sunilmallya/sshclaude",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0",
        "rich>=10.0",
        "requests>=2.25",
        "pyyaml>=5.4",
    ],
    entry_points={
        "console_scripts": [
            "sshclaude=sshclaude.cli:cli",
        ],
    },
)
