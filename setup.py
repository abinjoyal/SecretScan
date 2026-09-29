from setuptools import setup, find_packages

setup(
    name="secretscan",
    version="0.1.0",
    author="SecretScan Contributors",
    description="A local security utility to scan codebases for potential exposed secrets.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[
        "colorama>=0.4.6",
    ],
    extras_require={
        "dev": ["pytest>=7.0.0"],
    },
    entry_points={
        "console_scripts": [
            "secretscan=secretscan.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)
