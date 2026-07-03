#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
URLCHECKX - Gelişmiş URL Güvenlik Analiz Aracı
Developer : Vaelzor
Telegram : @nabicomeback
Version : 1.0.0
"""

import sys
import re
import json
import socket
import ssl
import datetime
import time
import argparse
from urllib.parse import urlparse, urljoin
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import http.client
import dns.resolver
import whois
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Renk kodları
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class URLScanner:
    def __init__(self, url, virus_total_api=None):
        self.url = url
        self.virus_total_api = virus_total_api
        self.results = {
            'url': url,
            'checks': {},
            'warnings': [],
            'risk_score': 0,
            'safe_checks': 0,
            'total_checks': 0
        }
        self.risk_factors = []
        
    def banner(self):
        banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════╗
║                                                          ║
║              {Colors.BOLD}URLCHECKX v1.0.0{Colors.CYAN}                      ║
║                                                          ║
║  {Colors.WHITE}Developer : Vaelzor{Colors.CYAN}                              ║
║  {Colors.WHITE}Telegram  : @nabicomeback{Colors.CYAN}                       ║
║                                                          ║
║  {Colors.YELLOW}🔒 URL Güvenlik Analiz Aracı{Colors.CYAN}                   ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝{Colors.END}
"""
        print(banner)

    def check_url_format(self):
        """URL formatını kontrol et"""
        try:
            parsed = urlparse(self.url)
            if not parsed.scheme:
                self.url = f"https://{self.url}"
                parsed = urlparse(self.url)
            
            if parsed.scheme not in ['http', 'https']:
                raise ValueError("Geçersiz URL şeması")
            
            self.results['checks']['url_format'] = {
                'status': '✓',
                'message': 'URL formatı geçerli'
            }
            self.results['total_checks'] += 1
            self.results['safe_checks'] += 1
            return True
        except Exception as e:
            self.results['checks']['url_format'] = {
                'status': '✗',
                'message': f'Geçersiz URL formatı: {str(e)}'
            }
            self.results['total_checks'] += 1
            self.risk_factors.append("Geçersiz URL formatı")
            return False

    def check_https(self):
        """HTTPS kontrolü"""
        try:
            parsed = urlparse(self.url)
            if parsed.scheme == 'https':
                self.results['checks']['https'] = {
                    'status': '✓',
                    'message': 'HTTPS kullanılıyor'
                }
                self.results['safe_checks'] += 1
            else:
                self.results['checks']['https'] = {
                    'status': '⚠',
                    'message': 'HTTPS kullanılmıyor (Güvensiz)'
                }
                self.risk_factors.append("HTTPS kullanılmıyor")
            self.results['total_checks'] += 1
        except Exception as e:
            self.results['checks']['https'] = {
                'status': '✗',
                'message': f'HTTPS kontrolü başarısız: {str(e)}'
            }
            self.results['total_checks'] += 1
            self.risk_factors.append("HTTPS kontrolü başarısız")

    def check_ssl_certificate(self):
        """SSL sertifikası kontrolü"""
        try:
            parsed = urlparse(self.url)
            hostname = parsed.hostname
            
            # SSL bağlantısı kontrol et
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Sertifika süresini kontrol et
                    not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    if datetime.datetime.now() < not_after:
                        self.results['checks']['ssl'] = {
                            'status': '✓',
                            'message': f'SSL sertifikası geçerli (Son kullanım: {not_after.strftime("%Y-%m-%d")})'
                        }
                        self.results['safe_checks'] += 1
                    else:
                        self.results['checks']['ssl'] = {
                            'status': '⚠',
                            'message': 'SSL sertifikası süresi dolmuş'
                        }
                        self.risk_factors.append("SSL sertifikası süresi dolmuş")
                    
            self.results['total_checks'] += 1
        except Exception as e:
            self.results['checks']['ssl'] = {
                'status': '⚠',
                'message': f'SSL sertifikası doğrulanamadı: {str(e)}'
            }
            self.results['total_checks'] += 1
            self.risk_factors.append("SSL sertifikası doğrulanamadı")

    def check_http_status(self):
        """HTTP durum kodu kontrolü"""
        try:
            response = requests.get(self.url, timeout=10, verify=False, allow_redirects=False)
            status_code = response.status_code
            
            if 200 <= status_code < 300:
                status_msg = 'Başarılı (OK)'
                self.results['safe_checks'] += 1
            elif 300 <= status_code < 400:
                status_msg = 'Yönlendirme'
                self.risk_factors.append(f"HTTP {status_code} - Yönlendirme")
            elif 400 <= status_code < 500:
                status_msg = 'İstemci hatası'
                self.risk_factors.append(f"HTTP {status_code} - İstemci hatası")
            elif 500 <= status_code < 600:
                status_msg = 'Sunucu hatası'
                self.risk_factors.append(f"HTTP {status_code} - Sunucu hatası")
            else:
                status_msg = 'Bilinmeyen durum'
                self.risk_factors.append(f"HTTP {status_code} - Bilinmeyen durum")
            
            self.results['checks']['http_status'] = {
                'status': '✓' if 200 <= status_code < 300 else '⚠',
                'message': f'HTTP {status_code}: {status_msg}'
            }
            self.results['total_checks'] += 1
            
        except requests.exceptions.ConnectionError:
            self.results['checks']['http_status'] = {
                'status': '✗',
                'message': 'Bağlantı hatası'
            }
            self.results['total_checks'] += 1
            self.risk_factors.append("Bağlantı hatası")
        except Exception as e:
            self.results['checks']['http_status'] = {
                'status': '✗',
                'message': f'Hata: {str(e)}'
            }
            self.results['total_checks'] += 1
            self.risk_factors.append(f"HTTP kontrol hatası: {str(e)}")

    def check_server_info(self):
        """Sunucu bilgisi kontrolü"""
        try:
            response = requests.get(self.url, timeout=10, verify=False)
            server = response.headers.get('Server', 'Bilinmiyor')
            
            self.results['checks']['server'] = {
                'status': '✓',
                'message': f'Sunucu: {server}'
            }
            self.results['total_checks'] += 1
            self.results['safe_checks'] += 1
        except Exception as e:
            self.results['checks']['server'] = {
                'status': '⚠',
                'message': f'Sunucu bilgisi alınamadı: {str(e)}'
            }
            self.results['total_checks'] += 1

    def check_security_headers(self):
        """Güvenlik başlıklarını kontrol et"""
        security_headers = {
            'X-Frame-Options': 'Clickjacking saldırılarına karşı koruma',
            'X-Content-Type-Options': 'MIME tipi saldırılarına karşı koruma',
            'X-XSS-Protection': 'XSS saldırılarına karşı koruma',
            'Strict-Transport-Security': 'HSTS ile HTTPS zorlaması',
            'Content-Security-Policy': 'CSP ile içerik güvenliği'
        }
        
        try:
            response = requests.get(self.url, timeout=10, verify=False)
            missing_headers = []
            
            for header, description in security_headers.items():
                if header in response.headers:
                    self.results['checks'][f'header_{header}'] = {
                        'status': '✓',
                        'message': f'{header}: {description}'
                    }
                    self.results['safe_checks'] += 1
                else:
                    missing_headers.append(header)
                    self.results['checks'][f'header_{header}'] = {
                        'status': '⚠',
                        'message': f'{header} eksik - {description}'
                    }
                    self.risk_factors.append(f"Eksik güvenlik başlığı: {header}")
                self.results['total_checks'] += 1
            
        except Exception as e:
            self.results['checks']['security_headers'] = {
                'status': '⚠',
                'message': f'Güvenlik başlıkları kontrol edilemedi: {str(e)}'
            }
            self.results['total_checks'] += 1

    def check_redirects(self):
        """Yönlendirme kontrolü"""
        try:
            response = requests.get(self.url, timeout=10, verify=False, allow_redirects=True)
            redirect_count = len(response.history)
            
            if redirect_count > 0:
                self.results['checks']['redirects'] = {
                    'status': '⚠' if redirect_count > 3 else '✓',
                    'message': f'{redirect_count} yönlendirme bulundu'
                }
                if redirect_count > 3:
                    self.risk_factors.append(f"Çok fazla yönlendirme ({redirect_count})")
            else:
                self.results['checks']['redirects'] = {
                    'status': '✓',
                    'message': 'Yönlendirme yok'
                }
                self.results['safe_checks'] += 1
            self.results['total_checks'] += 1
            
        except Exception as e:
            self.results['checks']['redirects'] = {
                'status': '⚠',
                'message': f'Yönlendirme kontrol edilemedi: {str(e)}'
            }
            self.results['total_checks'] += 1

    def check_domain_age(self):
        """Domain yaşı kontrolü"""
        try:
            parsed = urlparse(self.url)
            domain = parsed.hostname
            
            w = whois.whois(domain)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                age = (datetime.datetime.now() - creation_date).days
                age_years = age / 365.25
                
                if age < 30:
                    status = '⚠'
                    self.risk_factors.append(f"Alan adı çok yeni ({age} gün)")
                    message = f'{age} gün (30 günden az - YENİ)'
                elif age < 365:
                    status = '⚠'
                    self.risk_factors.append(f"Alan adı 1 yıldan az ({age} gün)")
                    message = f'{age} gün (1 yıldan az)'
                else:
                    status = '✓'
                    self.results['safe_checks'] += 1
                    message = f'{age_years:.1f} yıl'
                
                self.results['checks']['domain_age'] = {
                    'status': status,
                    'message': f'Domain yaşı: {message}'
                }
            else:
                self.results['checks']['domain_age'] = {
                    'status': '⚠',
                    'message': 'Domain yaşı bilgisi alınamadı'
                }
                self.risk_factors.append("Domain yaşı bilgisi alınamadı")
            self.results['total_checks'] += 1
            
        except Exception as e:
            self.results['checks']['domain_age'] = {
                'status': '⚠',
                'message': f'Domain yaşı kontrol edilemedi: {str(e)}'
            }
            self.results['total_checks'] += 1

    def check_ip_address(self):
        """IP adresi kontrolü"""
        try:
            parsed = urlparse(self.url)
            hostname = parsed.hostname
            
            ip = socket.gethostbyname(hostname)
            
            # IP ile açılıp açılmadığını kontrol et
            is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname))
            
            if is_ip:
                self.results['checks']['ip'] = {
                    'status': '⚠',
                    'message': f'IP: {ip} (Doğrudan IP kullanımı - Riskli)'
                }
                self.risk_factors.append("Doğrudan IP adresi kullanımı")
            else:
                self.results['checks']['ip'] = {
                    'status': '✓',
                    'message': f'IP: {ip}'
                }
                self.results['safe_checks'] += 1
            self.results['total_checks'] += 1
            
        except Exception as e:
            self.results['checks']['ip'] = {
                'status': '⚠',
                'message': f'IP adresi alınamadı: {str(e)}'
            }
            self.results['total_checks'] += 1

    def check_url_structure(self):
        """URL yapısını kontrol et"""
        try:
            parsed = urlparse(self.url)
            suspicious = False
            warnings = []
            
            # Uzunluk kontrolü
            if len(self.url) > 100:
                suspicious = True
                warnings.append("URL çok uzun (>100 karakter)")
                self.risk_factors.append("URL çok uzun")
            
            # Şüpheli karakterler
            suspicious_chars = ['%', '@', ';', '&', '=', '?']
            for char in suspicious_chars:
                if char in parsed.path:
                    suspicious = True
                    warnings.append(f"Şüpheli karakter: '{char}'")
                    self.risk_factors.append(f"URL'de şüpheli karakter: '{char}'")
                    break
            
            # Alt alan adı kontrolü
            if parsed.hostname:
                subdomain_count = parsed.hostname.count('.')
                if subdomain_count > 3:
                    suspicious = True
                    warnings.append("Çok fazla alt alan adı")
                    self.risk_factors.append("Çok fazla alt alan adı")
            
            if suspicious:
                self.results['checks']['url_structure'] = {
                    'status': '⚠',
                    'message': f'Şüpheli URL yapısı: {", ".join(warnings[:2])}'
                }
            else:
                self.results['checks']['url_structure'] = {
                    'status': '✓',
                    'message': 'URL yapısı normal'
                }
                self.results['safe_checks'] += 1
            self.results['total_checks'] += 1
            
        except Exception as e:
            self.results['checks']['url_structure'] = {
                'status': '⚠',
                'message': f'URL yapısı kontrol edilemedi: {str(e)}'
            }
            self.results['total_checks'] += 1

    def check_dns_records(self):
        """DNS kayıtları kontrolü"""
        try:
            parsed = urlparse(self.url)
            domain = parsed.hostname
            
            dns_records = {}
            record_types = ['A', 'MX', 'NS', 'TXT']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(r) for r in answers]
                except:
                    dns_records[record_type] = []
            
            if dns_records['A']:
                self.results['checks']['dns'] = {
                    'status': '✓',
                    'message': f'DNS kayıtları mevcut (A: {len(dns_records["A"])}, MX: {len(dns_records["MX"])}, NS: {len(dns_records["NS"])})'
                }
                self.results['safe_checks'] += 1
            else:
                self.results['checks']['dns'] = {
                    'status': '⚠',
                    'message': 'DNS kaydı bulunamadı'
                }
                self.risk_factors.append("DNS kaydı bulunamadı")
            self.results['total_checks'] += 1
            
        except Exception as e:
            self.results['checks']['dns'] = {
                'status': '⚠',
                'message': f'DNS kontrol edilemedi: {str(e)}'
            }
            self.results['total_checks'] += 1

    def check_virustotal(self):
        """VirusTotal API ile kontrol"""
        if not self.virus_total_api:
            self.results['checks']['virustotal'] = {
                'status': 'ℹ',
                'message': 'VirusTotal API anahtarı sağlanmadı (opsiyonel)'
            }
            self.results['total_checks'] += 1
            return
        
        try:
            parsed = urlparse(self.url)
            domain = parsed.hostname
            headers = {
                'x-apikey': self.virus_total_api
            }
            response = requests.get(
                f'https://www.virustotal.com/api/v3/domains/{domain}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and 'attributes' in data['data']:
                    attributes = data['data']['attributes']
                    malicious = attributes.get('last_analysis_stats', {}).get('malicious', 0)
                    
                    if malicious > 0:
                        self.results['checks']['virustotal'] = {
                            'status': '⚠',
                            'message': f'VirusTotal: {malicious} kötü amaçlı rapor bulundu'
                        }
                        self.risk_factors.append(f"VirusTotal'de {malicious} kötü amaçlı rapor")
                    else:
                        self.results['checks']['virustotal'] = {
                            'status': '✓',
                            'message': 'VirusTotal: Şüpheli rapor bulunamadı'
                        }
                        self.results['safe_checks'] += 1
            else:
                self.results['checks']['virustotal'] = {
                    'status': '⚠',
                    'message': f'VirusTotal hatası: {response.status_code}'
                }
            self.results['total_checks'] += 1
            
        except Exception as e:
            self.results['checks']['virustotal'] = {
                'status': '⚠',
                'message': f'VirusTotal kontrol edilemedi: {str(e)}'
            }
            self.results['total_checks'] += 1

    def calculate_risk_score(self):
        """Risk skoru hesapla"""
        risk_weight = {
            "HTTPS kullanılmıyor": 15,
            "SSL sertifikası süresi dolmuş": 10,
            "SSL sertifikası doğrulanamadı": 15,
            "Geçersiz URL formatı": 10,
            "HTTP 3xx - Yönlendirme": 5,
            "HTTP 4xx - İstemci hatası": 10,
            "HTTP 5xx - Sunucu hatası": 10,
            "Bağlantı hatası": 20,
            "Eksik güvenlik başlığı": 5,
            "Çok fazla yönlendirme": 8,
            "Alan adı çok yeni": 12,
            "Alan adı 1 yıldan az": 8,
            "Doğrudan IP adresi kullanımı": 15,
            "URL çok uzun": 3,
            "URL'de şüpheli karakter": 5,
            "Çok fazla alt alan adı": 5,
            "DNS kaydı bulunamadı": 10,
            "VirusTotal'de kötü amaçlı rapor": 20
        }
        
        total_risk = 0
        for factor in self.risk_factors:
            # En uygun risk ağırlığını bul
            found = False
            for key, weight in risk_weight.items():
                if key.lower() in factor.lower() or factor.lower() in key.lower():
                    total_risk += weight
                    found = True
                    break
            if not found:
                total_risk += 5  # Bilinmeyen risk faktörü
        
        # Sınırlandır
        total_risk = min(total_risk, 100)
        self.results['risk_score'] = total_risk
        
        # Risk seviyesi
        if total_risk <= 20:
            risk_level = "Düşük"
        elif total_risk <= 50:
            risk_level = "Orta"
        elif total_risk <= 75:
            risk_level = "Yüksek"
        else:
            risk_level = "Kritik"
        
        self.results['risk_level'] = risk_level

    def print_results(self):
        """Sonuçları yazdır"""
        self.banner()
        
        print(f"\n{Colors.BOLD}🎯 HEDEF:{Colors.END} {self.url}\n")
        print(f"{Colors.BOLD}═══════════════════════════════════════════════════════════{Colors.END}\n")
        
        # Kontrol sonuçları
        for check_name, check_data in self.results['checks'].items():
            status = check_data['status']
            message = check_data['message']
            
            if status == '✓':
                color = Colors.GREEN
                icon = '✅'
            elif status == '⚠':
                color = Colors.YELLOW
                icon = '⚠️'
            elif status == '✗':
                color = Colors.RED
                icon = '❌'
            else:
                color = Colors.CYAN
                icon = 'ℹ️'
            
            print(f"{color}{icon} {message}{Colors.END}")
        
        print(f"\n{Colors.BOLD}═══════════════════════════════════════════════════════════{Colors.END}")
        
        # Güvenlik metrikleri
        print(f"\n{Colors.BOLD}📊 GÜVENLİK METRİKLERİ:{Colors.END}")
        print(f"   ✅ Başarılı kontroller: {self.results['safe_checks']}/{self.results['total_checks']}")
        print(f"   ⚠️  Risk faktörleri: {len(self.risk_factors)}")
        
        if self.risk_factors:
            print(f"\n{Colors.YELLOW}🔴 RİSK FAKTÖRLERİ:{Colors.END}")
            for i, factor in enumerate(self.risk_factors[:5], 1):
                print(f"   {i}. {factor}")
            if len(self.risk_factors) > 5:
                print(f"   ... ve {len(self.risk_factors) - 5} faktör daha")
        
        # Risk skoru
        risk_score = self.results['risk_score']
        risk_level = self.results['risk_level']
        
        if risk_score <= 20:
            color = Colors.GREEN
            bar = '🟢'
        elif risk_score <= 50:
            color = Colors.YELLOW
            bar = '🟡'
        elif risk_score <= 75:
            color = Colors.RED
            bar = '🔴'
        else:
            color = Colors.RED
            bar = '🔥'
        
        print(f"\n{Colors.BOLD}⚠️ RİSK SKORU:{Colors.END} {color}{risk_score}/100 ({risk_level}){Colors.END}")
        print(f"   {bar * (risk_score // 10)}")
        
        # Bilgi
        print(f"\n{Colors.CYAN}📌 NOT: Bu araç sadece bilgilendirme amaçlıdır.{Colors.END}")
        print(f"{Colors.CYAN}   Bir sitenin güvenli olduğunu garanti etmez.{Colors.END}")
        
        # Özet
        if risk_score <= 20:
            print(f"\n{Colors.GREEN}✅ Sonuç: Site güvenli görünüyor. Dikkatli olmaya devam edin.{Colors.END}")
        elif risk_score <= 50:
            print(f"\n{Colors.YELLOW}⚠️ Sonuç: Bazı risk faktörleri var. Dikkatli olun.{Colors.END}")
        elif risk_score <= 75:
            print(f"\n{Colors.RED}🔴 Sonuç: Yüksek risk tespit edildi! Siteyi ziyaret etmeyin.{Colors.END}")
        else:
            print(f"\n{Colors.RED}🔥 Sonuç: KRİTİK RİSK! Siteyi ziyaret ETMEYİN!{Colors.END}")

def main():
    parser = argparse.ArgumentParser(
        description='URLCHECKX - Gelişmiş URL Güvenlik Analiz Aracı',
        epilog='Geliştirici: Vaelzor | Telegram: @nabicomeback'
    )
    parser.add_argument('url', help='Analiz edilecek URL')
    parser.add_argument('--vt', help='VirusTotal API anahtarı (opsiyonel)')
    parser.add_argument('--version', action='version', version='URLCHECKX v1.0.0\nGeliştirici: Vaelzor\nTelegram: @nabicomeback')
    
    args = parser.parse_args()
    
    scanner = URLScanner(args.url, args.vt)
    
    # Tüm kontrolleri çalıştır
    scanner.check_url_format()
    scanner.check_https()
    scanner.check_ssl_certificate()
    scanner.check_http_status()
    scanner.check_server_info()
    scanner.check_security_headers()
    scanner.check_redirects()
    scanner.check_domain_age()
    scanner.check_ip_address()
    scanner.check_url_structure()
    scanner.check_dns_records()
    scanner.check_virustotal()
    scanner.calculate_risk_score()
    
    # Sonuçları göster
    scanner.print_results()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️ İşlem iptal edildi.{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}❌ Hata: {str(e)}{Colors.END}")
        sys.exit(1)
