"""
Ağ Trafiği İzleme Aracı

Bu Python scripti, bağlı olduğunuz ağın trafiğini izlemek ve ICMP, TCP, UDP gibi protokollere ait paketlerin canlı grafiklerini göstermek amacıyla geliştirilmiştir. 
Kullanıcı, ağdaki trafiği gerçek zamanlı olarak izleyebilir ve hangi protokollerin ne sıklıkla kullanıldığını gözlemleyebilir. 

Amaç:
- Sisteminize bağlı ağ üzerinden geçen veri trafiğini izlemek.
- Protokol bazlı (ICMP, TCP, UDP) paket sayısını canlı olarak bir grafik üzerinde görüntülemek.
- Ağ yöneticileri veya güvenlik uzmanları için ağ trafiğini analiz etmeyi kolaylaştırmak.
- Potansiyel ağ anormalliklerini fark ederek hızlı aksiyon almayı sağlamak.

Kullanılan Teknolojiler:
- **Scapy**: Ağ trafiğini dinlemek ve paket yakalamak için kullanılan Python kütüphanesi.
- **Matplotlib**: Paket verilerini grafiksel olarak görüntülemek için kullanılan kütüphane.
- **Threading**: Aynı anda hem ağ trafiğini yakalayıp hem de grafikleri güncellemeyi sağlamak için iş parçacığı kullanımı.

Nasıl Çalışır:
1. Scapy ile bağlı olduğunuz ağdaki paketler dinlenir.
2. Her bir paketin protokolü belirlenir (ICMP, TCP, UDP) ve bir sayaçta toplanır.
3. Matplotlib ile her saniye güncellenen bir grafik oluşturulur, böylece zaman içinde ağ trafiğinin değişimi izlenebilir.
4. Python Threading ile ağ trafiği yakalama işlemi arka planda gerçekleştirilirken, ana iş parçacığında grafik animasyonu sürer.

"""

from scapy.all import sniff, conf
from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import threading
import psutil

from scapy.all import sniff
from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import threading

protocol_counter = Counter()

protocols = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
}

def packet_sniffer(packet):
    if packet.haslayer("IP"):
        protocol = packet.getlayer("IP").proto
        protocol_counter[protocol] += 1

def start_sniffing(interface=None):
    if interface is None:
        # Windows'ta doğru ağ arayüzü adını buraya yaz 
        interface = r"\Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"
    print(f"Yakalama başlatıldı: {interface}")
    sniff(iface=interface, prn=packet_sniffer, store=False)


x_vals = []
y_vals = []


def update_graph(frame):
    x_vals.append(len(x_vals))  
    y_vals.append([protocol_counter[1], protocol_counter[6], protocol_counter[17]])  # ICMP, TCP, UDP
    plt.cla()  

   
    plt.stackplot(x_vals, list(zip(*y_vals)), labels=['ICMP', 'TCP', 'UDP'])
    plt.legend(loc='upper left')
    plt.title("Ağ Trafiği İzleme")
    plt.ylabel("Paket Sayısı")
    plt.xlabel("Zaman")


def start_graph():
    fig = plt.figure()
    ani = FuncAnimation(plt.gcf(), update_graph, interval=1000)  # 1 saniyede bir günceller
    plt.show()

if __name__ == "__main__":
   
    sniff_thread = threading.Thread(target=start_sniffing, args=(None,))
    sniff_thread.daemon = True
    sniff_thread.start()

    start_graph()
