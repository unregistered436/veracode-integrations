from setuptools import setup, find_packages

setup(
    name="veracodeflawaging",
    version="1.5",
    packages=find_packages(),
    license="MIT",
    author="Patrick McNeil & Chris Campbell",
    url="https://www.veracode.com",
    author_email="pmcneil@veracode.com",
    description="Generate a Veracode flaw aging report",
    install_requires=[
        "requests >= 2.21.0",
        "security-apisigning-python >= 17.9.1"
    ],
    entry_points={
        "console_scripts": ["veracodeflawaging = veracodeflawaging.main:main"]
    }
)