from setuptools import setup, find_packages

setup(
    name="lvc-ssi-framework",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
        "pyjwt>=2.8.0",
        "aiofiles>=23.2.1",
        "asyncio>=3.4.3",
    ],
    python_requires=">=3.8",
) 