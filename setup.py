#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
URLCHECKX - Setup Configuration
Developer : Vaelzor
Telegram : @nabicomeback
Repository: https://github.com/vaelzor/URLCHECKX
"""

from setuptools import setup, find_packages
import os
import re

# Versiyon bilgisini oku
with open("urlcheck.py", "r", encoding="utf-8") as f:
    content = f.read()
    version_match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
    if version_match:
        version = version_match.group(1)
    else:
        version = "1.0.0"

# README'yi oku
try:
    with open("README.md", "r", encoding="utf-8") as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "URLCHECKX - Gelişmiş URL Güvenlik Analiz Aracı"

# Gereksinimleri oku
try:
    with open("requirements.txt", "r", encoding="utf-8") as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]
except FileNotFoundError:
    requirements = [
        "requests>=2.28.0",
        "dnspython>=2.2.0",
        "python-whois>=0.7.0",
        "colorama>=0.4.6",
        "urllib3>=1.26.0"
    ]

setup(
    # Temel Bilgiler
    name="urlcheckx",
    version=version,
    author="Vaelzor",
    author_email="nabigeridondu990@gmail.com",
    description="🔒 URLCHECKX - Gelişmiş URL Güvenlik Analiz Aracı",
    long_description=long_description,
    long_description_content_type="text/markdown",
    
    # URL'ler
    url="https://github.com/vaelzor/URLCHECKX",
    project_urls={
        "Bug Reports": "https://github.com/vaelzor/URLCHECKX/issues",
        "Source Code": "https://github.com/vaelzor/URLCHECKX",
        "Documentation": "https://github.com/vaelzor/URLCHECKX#readme",
        "Telegram": "https://t.me/nabicomeback",
    },
    
    # Paket Bilgileri
    packages=find_packages(),
    py_modules=["urlcheck"],
    include_package_data=True,
    
    # Bağımlılıklar
    python_requires=">=3.6",
    install_requires=requirements,
    
    # Ekstra bağımlılıklar
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.990",
            "twine>=4.0.0",
            "build>=0.9.0",
        ],
        "virustotal": [
            "virustotal-api>=1.0.0",
        ],
    },
    
    # CLI Entry Point
    entry_points={
        "console_scripts": [
            "urlcheckx=urlcheck:main",
            "urlcheck=urlcheck:main",  # Alternatif isim
        ],
    },
    
    # Sınıflandırma
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking :: Monitoring",
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
        "Natural Language :: English",
        "Natural Language :: Turkish",
    ],
    
    # Anahtar Kelimeler
    keywords=[
        "security",
        "url-scanner",
        "phishing-detection",
        "malware-analysis",
        "cybersecurity",
        "vulnerability-scanner",
        "ssl-checker",
        "domain-age",
        "virustotal",
        "risk-scoring",
        "url-analysis",
        "website-security",
    ],
    
    # Minimum Python sürümü
    python_requires=">=3.6",
    
    # Zip safe
    zip_safe=False,
    
    # Metadata
    license="MIT",
    platforms=["any"],
)

# Kurulum sonrası mesajı
print("""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║          🚀 URLCHECKX Başarıyla Kuruldu!               ║
║                                                          ║
║  Kullanım:                                              ║
║  $ urlcheckx https://example.com                       ║
║                                                          ║
║  Developer : Vaelzor                                    ║
║  Telegram  : @nabicomeback                             ║
║                                                          ║
║  📌 Yardım için: urlcheckx --help                      ║
║  📌 Versiyon: urlcheckx --version                     ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
""")
