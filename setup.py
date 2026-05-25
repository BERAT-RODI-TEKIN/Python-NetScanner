from setuptools import setup, find_packages
setup(
    name="netscanner",
    version="3.0.0",
    description="NetScanner — Full Release: Professional Port Scanner CLI+GUI",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    python_requires=">=3.8",
    packages=find_packages(exclude=["tests*"]),
    entry_points={
        "console_scripts": [
            "netscanner=netscanner.cli.cli:run_cli",
        ],
    },
)
