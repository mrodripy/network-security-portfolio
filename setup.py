from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="network-security-scanner",
    version="1.0.0",
    author="Tu Nombre",
    author_email="tu.email@example.com",
    description="Advanced Network Security Scanner with comprehensive reporting",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tuusuario/network-security-portfolio",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "netsec-scan=portfolio_scanner:main",
        ],
    },
    keywords="security, nmap, network, scanner, pentesting, cybersecurity",
)
