import os
import json
import threading
import smtplib
from email.message import EmailMessage
from datetime import datetime
from dotenv import load_dotenv
from scapy.all import sniff, IP, Ether, DNSQR, TCP, Raw
from ipwhois import IPWhois

# Cargar variables de entorno
load_dotenv()
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_APP_PASSWORD")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")

# Estructuras de datos y estados
whitelist = {"ips": [], "macs": []}
blacklist = set()
alerted_unknowns = set() # Evitar spam de correos por la misma IP desconocida
alerted_threats = set()  # Evitar spam de correos por la misma amenaza

def cargar_listas():
    global whitelist, blacklist
    # Cargar lista blanca
    if os.path.exists('whitelist.json'):
        with open('whitelist.json', 'r') as f:
            data = json.load(f)
            whitelist['ips'] = data.get('ips', [])
            whitelist['macs'] = [mac.lower() for mac in data.get('macs', [])]
    
    # Cargar lista negra
    if os.path.exists('blacklist.txt'):
        with open('blacklist.txt', 'r') as f:
            blacklist = set(line.strip() for line in f if line.strip())

def enviar_correo(asunto, cuerpo):
    """Función genérica para enviar correos de manera segura."""
    try:
        msg = EmailMessage()
        msg.set_content(cuerpo)
        msg['Subject'] = asunto
        msg['From'] = SMTP_USER
        msg['To'] = ADMIN_EMAIL

        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print(f"[*] Correo enviado a {ADMIN_EMAIL}: {asunto}")
    except Exception as e:
        print(f"[!] Error al enviar correo: {e}")

def manejar_intruso(ip_src, mac_src):
    """Módulo 1: Alerta de equipo no autorizado en Capa 2/3."""
    identifier = f"{ip_src}-{mac_src}"
    if identifier not in alerted_unknowns:
        alerted_unknowns.add(identifier)
        asunto = "Alerta IDS: Dispositivo No Autorizado Detectado"
        cuerpo = f"Se ha detectado tráfico de un dispositivo no registrado en la lista blanca.\n\nIP Origen: {ip_src}\nMAC Origen: {mac_src}\nFecha: {datetime.now()}"
        print(f"[!] INTRUSO DETECTADO: {ip_src} ({mac_src})")
        # Enviar correo en un hilo paralelo
        threading.Thread(target=enviar_correo, args=(asunto, cuerpo)).start()

def automatizacion_forense_y_alerta(ip_dst):
    """Módulos 3 y 4: Alerta de Emergencia y consulta Whois/Abuse."""
    if ip_dst not in alerted_threats:
        alerted_threats.add(ip_dst)
        print(f"[!!!] CONEXIÓN PELIGROSA DETECTADA HACIA: {ip_dst}")
        
        # Módulo 4: Automatización Forense (Obtener datos de abuso)
        datos_abuso = "No se pudo obtener información de Whois."
        try:
            obj = IPWhois(ip_dst)
            res = obj.lookup_rdap(depth=1)
            # Extraer correos de abuso si existen en la respuesta RDAP
            entidades = res.get('objects', {})
            correos_abuso = []
            for ent_id, ent_data in entidades.items():
                contactos = ent_data.get('contact', {})
                emails = contactos.get('email', [])
                if emails:
                    for email in emails:
                        if email.get('value'):
                            correos_abuso.append(email['value'])
            
            if correos_abuso:
                datos_abuso = f"Contactos de Abuso detectados: {', '.join(set(correos_abuso))}\nASN: {res.get('asn_description')}"
        except Exception as e:
            datos_abuso = f"Error en consulta Whois: {e}"

        # Ensamblar y enviar Alerta de Emergencia
        asunto = "ALERTA DE EMERGENCIA: Conexión a IP Maliciosa (Riesgo: Virus/Botnet)"
        cuerpo = f"""Se ha detectado tráfico hacia una IP registrada en la lista negra.

IP Destino (Maliciosa): {ip_dst}
Fecha y Hora: {datetime.now()}

=== REPORTE FORENSE AUTOMATIZADO (WHOIS/ABUSE) ===
{datos_abuso}

Por favor, proceda a reportar esta IP o bloquearla en el firewall perimetral.
"""
        enviar_correo(asunto, cuerpo)

def procesar_paquete(packet):
    # Validar que el paquete tenga capa IP y Ethernet (Capa 3 y 2)
    if IP in packet and Ether in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        mac_src = packet[Ether].src.lower()

        # Ignorar tráfico loopback o broadcast común para evitar falsos positivos de la propia máquina
        if ip_src == "127.0.0.1" or ip_src.startswith("169.254."):
            return

        # ==========================================
        # Módulo 1: Listas Blancas (Capa 2 y 3)
        # ==========================================
        if ip_src not in whitelist['ips'] or mac_src not in whitelist['macs']:
            manejar_intruso(ip_src, mac_src)

        # ==========================================
        # Módulo 2: Monitoreo de Sitios (Reporte)
        # ==========================================
        # Extraer consultas DNS
        if packet.haslayer(DNSQR) and packet[DNSQR].qname:
            dominio = packet[DNSQR].qname.decode('utf-8').strip('.')
            # Imprimir bitácora en tiempo real (puedes redirigir esto a un archivo de log)
            print(f"[LOG - DNS] IP: {ip_src} visitó -> {dominio}")

        # Extraer peticiones HTTP en texto plano (Host header)
        elif packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if "HTTP" in payload and "Host:" in payload:
                for linea in payload.split('\r\n'):
                    if linea.startswith("Host:"):
                        dominio_http = linea.split(" ")[1].strip()
                        print(f"[LOG - HTTP] IP: {ip_src} visitó -> {dominio_http}")

        # ==========================================
        # Módulos 3 y 4: IPs Peligrosas y Forense
        # ==========================================
        if ip_dst in blacklist:
            # Despachar a un hilo para no bloquear la captura de paquetes por la consulta a la API
            threading.Thread(target=automatizacion_forense_y_alerta, args=(ip_dst,)).start()

if __name__ == "__main__":
    print("[*] Iniciando Sistema IDS Institucional...")
    cargar_listas()
    print(f"[*] Lista blanca cargada: {len(whitelist['ips'])} IPs, {len(whitelist['macs'])} MACs.")
    print(f"[*] Lista negra cargada: {len(blacklist)} IPs maliciosas.")
    print("[*] Sniffer activo. Monitoreando tráfico (Presiona Ctrl+C para detener)...")
    
    try:
        # sniff() bloquea el hilo principal y procesa cada paquete con procesar_paquete
        sniff(prn=procesar_paquete, store=False)
    except KeyboardInterrupt:
        print("\n[*] Apagando IDS. Captura finalizada.")