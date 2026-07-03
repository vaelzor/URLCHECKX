#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
URLCHECKX - Setup Configuration
Developer : Vaelzor
Telegram : @nabicomeback
Repository: https://github.com/vaelzor/URLCHECKX
"""

from setuptools import setup, find_packages
import re

# Versiyon bilgisini oku
with open("urlcheckx.py", "r", encoding="utf-8") as f:
    content = f.read()
    version_match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
    if version_match:
        version = version_match.group(1)
    else:
        version = "1.0.0"

setup(
    name="urlcheckx",
    version=version,
    author="Vaelzor",
    author_email="vaelzor@protonmail.com",
    description="🔒 URLCHECKX - Gelişmiş URL Güvenlik Analiz Aracı",
    long_description="URLCHECKX - 12 farklı güvenlik kontrolü ile URL analizi",
    long_description_content_type="text/markdown",
    url="https://github.com/vaelzor/URLCHECKX",
    project_urls={
        "Bug Reports": "https://github.com/vaelzor/URLCHECKX/issues",
        "Source Code": "https://github.com/vaelzor/URLCHECKX",
        "Telegram": "https://t.me/nabicomeback",
    },
    py_modules=["urlcheckx"],
    python_requires=">=3.6",
    install_requires=[
        "requests>=2.28.0",
        "dnspython>=2.2.0",
        "python-whois>=0.7.0",
        "colorama>=0.4.6",
        "urllib3>=1.26.0"
    ],
    entry_points={
        "console_scripts": [
            "urlcheckx=urlcheckx:main",
            "urlcheck=urlcheckx:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords=[
        "security",
        "url-scanner",
        "phishing-detection",
        "malware-analysis",
        "cybersecurity",
        "ssl-checker",
        "domain-age",
        "virustotal",
        "risk-scoring",
    ],
    license="MIT",
)
