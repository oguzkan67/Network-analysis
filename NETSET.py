import psutil
import socket
import scapy.all as scapy
import tkinter as tk
from tkinter import simpledialog

# Ağ bilgilerini alma fonksiyonu
def get_network_info():
    try:
        ip_address = socket.gethostbyname(socket.gethostname())  # Yerel IP
        net_info = psutil.net_if_addrs()
        
        network_details = f"IP Adresi: {ip_address}\n\n"
        
        # Ağ arayüzlerinin bilgilerini daha temiz yazdırma
        for interface, addrs in net_info.items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    network_details += f"Ağ Arayüzü: {interface}\n"
                    network_details += f"IP Adresi: {addr.address}\n"
                    network_details += f"Ağ Maskesi: {addr.netmask}\n"
                    network_details += f"Yayın Adresi: {addr.broadcast}\n\n"
        
        return network_details
    except Exception as e:
        return f"Hata oluştu: {str(e)}"

# Ağa bağlı cihazları tarama
def scan_network(network):
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    devices_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for device in devices_list:
        devices.append(device[1].psrc)
    
    return devices

# Port taraması
def scan_ports(ip, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):  # Kullanıcının seçtiği aralıkta portları tara
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    return open_ports

# GUI arayüzü
class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ağ Tarayıcı Uygulaması")
        self.root.geometry("500x450")
        
        self.label = tk.Label(self.root, text="Ağ Bilgileri", font=("Arial", 16))
        self.label.pack(pady=20)
        
        self.info_button = tk.Button(self.root, text="Ağ Bilgilerini Al", command=self.display_network_info)
        self.info_button.pack(pady=10)
        
        self.scan_button = tk.Button(self.root, text="Ağa Bağlı Cihazları Tara", command=self.scan_network)
        self.scan_button.pack(pady=10)
        
        self.port_button = tk.Button(self.root, text="Port Taraması Yap", command=self.scan_ports_ui)
        self.port_button.pack(pady=10)
        
        self.output_text = tk.Text(self.root, height=10, width=50)
        self.output_text.pack(pady=20)
    
    # Ağ bilgilerini GUI'ye yazdırma
    def display_network_info(self):
        network_info = get_network_info()
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, network_info)
    
    # Ağa bağlı cihazları tarama ve gösterme
    def scan_network(self):
        network = "192.168.1.1/24"  # Tarama yapılacak ağ adresi
        devices = scan_network(network)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "Bağlı Cihazlar:\n")
        for device in devices:
            self.output_text.insert(tk.END, f"IP: {device}\n")
    
    # Port taraması yapma
    def scan_ports_ui(self):
        ip = "192.168.1.1"  # Taranacak IP
        start_port = simpledialog.askinteger("Port Başlangıç", "Başlangıç port numarasını girin:", parent=self.root, minvalue=1, maxvalue=65535)
        end_port = simpledialog.askinteger("Port Bitiş", "Bitiş port numarasını girin:", parent=self.root, minvalue=1, maxvalue=65535)
        
        if start_port and end_port:
            open_ports = scan_ports(ip, start_port, end_port)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"{ip} için açık portlar (aralık: {start_port}-{end_port}):\n")
            if open_ports:
                for port in open_ports:
                    self.output_text.insert(tk.END, f"Port {port} açık\n")
            else:
                self.output_text.insert(tk.END, "Hiç açık port bulunamadı.\n")
        else:
            messagebox.showwarning("Geçersiz Giriş", "Lütfen geçerli bir port aralığı girin.")

# Ana program
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
