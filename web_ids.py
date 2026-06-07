import os
import json
import threading
import smtplib
import csv
import io
import subprocess
import logging
import webbrowser
import requests
from threading import Timer
from collections import deque
from email.message import EmailMessage
from datetime import datetime
from flask import Flask, render_template, request, make_response
from flask_socketio import SocketIO
from dotenv import load_dotenv
from scapy.all import sniff, IP, Ether, DNSQR, TCP, Raw
from ipwhois import IPWhois

# ==========================================
# CONFIGURACIÓN DE CONSOLA (ESTILO NOTHING)
# ==========================================
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

class NColor:
    RED = '\033[91m'
    GREEN = '\033[92m'
    DIM = '\033[90m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_log(tipo, mensaje):
    hora = datetime.now().strftime("%H:%M:%S")
    if tipo == "TRAFFIC":
        print(f"{NColor.DIM}[{hora}]{NColor.RESET} {NColor.WHITE}NET_LOG{NColor.RESET} > {mensaje}")
    elif tipo == "ALERT":
        print(f"\n{NColor.RED}{NColor.BOLD}[!!!] {mensaje}{NColor.RESET}\n")
    elif tipo == "INFO":
        print(f"{NColor.GREEN}[*] {mensaje}{NColor.RESET}")

# ==========================================
# INICIALIZACIÓN
# ==========================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

load_dotenv()
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_APP_PASSWORD")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
VT_API_KEY = os.getenv("VT_API_KEY")

whitelist = {"ips": [], "macs": []}
blacklist = set()
alerted_unknowns = set()
alerted_threats = set()

intrusos_lote = [] 
traffic_log = deque(maxlen=300) 

# ==========================================
# LÓGICA DEL IDS
# ==========================================
def cargar_listas():
    global whitelist, blacklist
    if os.path.exists('whitelist.json'):
        with open('whitelist.json', 'r') as f:
            data = json.load(f)
            whitelist['ips'] = data.get('ips', [])
            whitelist['macs'] = [mac.lower() for mac in data.get('macs', [])]
    
    if os.path.exists('blacklist.txt'):
        with open('blacklist.txt', 'r') as f:
            blacklist = set(line.strip() for line in f if line.strip())
    
    print_log("INFO", f"Listas cargadas: {len(whitelist['ips'])} IPs permitidas, {len(blacklist)} amenazas en Blacklist.")

def guardar_whitelist():
    with open('whitelist.json', 'w') as f:
        json.dump(whitelist, f, indent=4)

def enviar_correo(asunto, cuerpo):
    try:
        msg = EmailMessage()
        msg.set_content(cuerpo)
        msg['Subject'] = asunto
        msg['From'] = SMTP_USER
        msg['To'] = ADMIN_EMAIL
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print_log("INFO", f"Correo enviado a {ADMIN_EMAIL}")
    except Exception as e:
        print_log("ALERT", f"Error enviando correo: {e}")

def manejar_intruso(ip_src, mac_src):
    global intrusos_lote
    identifier = f"{ip_src}-{mac_src}"
    if identifier not in alerted_unknowns:
        alerted_unknowns.add(identifier)
        hora_actual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print_log("ALERT", f"INTRUSO CAPA 2/3 DETECTADO | IP: {ip_src} | MAC: {mac_src}")
        
        socketio.emit('alerta', {
            'tipo': 'INTRUSO CAPA 2/3', 
            'ip': ip_src, 
            'mac': mac_src, 
            'hora': hora_actual,
            'mensaje': f'No Autorizado. IP: {ip_src}'
        })
        
        intrusos_lote.append({'ip': ip_src, 'mac': mac_src, 'hora': hora_actual})
        if len(intrusos_lote) >= 10:
            print_log("INFO", "Lote de 10 intrusos alcanzado. Enviando reporte...")
            asunto = "Alerta IDS: Lote de 10 Dispositivos No Autorizados"
            cuerpo = "Se han detectado los siguientes 10 dispositivos no registrados en la lista blanca:\n\n"
            for idx, intruso in enumerate(intrusos_lote):
                cuerpo += f"{idx + 1}. IP: {intruso['ip']} | MAC: {intruso['mac']} | Hora: {intruso['hora']}\n"
            
            threading.Thread(target=enviar_correo, args=(asunto, cuerpo)).start()
            intrusos_lote.clear()

def automatizacion_forense(ip_dst):
    if ip_dst not in alerted_threats:
        alerted_threats.add(ip_dst)
        hora_actual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print_log("ALERT", f"CONEXIÓN A BLACKLIST | IP MALICIOSA: {ip_dst} | INICIANDO FORENSE...")
        
        socketio.emit('alerta', {
            'tipo': 'AMENAZA (Virus/Botnet)', 
            'ip': ip_dst,
            'hora': hora_actual,
            'mensaje': f'Conexión a Blacklist: {ip_dst}'
        })
        
        datos_abuso = "No se pudo obtener información."
        try:
            obj = IPWhois(ip_dst)
            res = obj.lookup_rdap(depth=1)
            
            correos_abuso = []
            objetos = res.get('objects')
            
            if objetos and isinstance(objetos, dict):
                for ent_data in objetos.values():
                    if ent_data and isinstance(ent_data, dict):
                        contactos = ent_data.get('contact')
                        if contactos and isinstance(contactos, dict):
                            emails = contactos.get('email')
                            if emails and isinstance(emails, list):
                                for email in emails:
                                    if email and isinstance(email, dict) and email.get('value'):
                                        correos_abuso.append(email['value'])
            
            asn_desc = res.get('asn_description', 'No disponible')
            
            if correos_abuso:
                datos_abuso = f"Contactos de Abuso: {', '.join(set(correos_abuso))}\nASN: {asn_desc}"
                print_log("INFO", f"Forense completado. Contactos extraídos: {len(set(correos_abuso))}")
            else:
                datos_abuso = f"No hay correos públicos de soporte registrados.\nASN: {asn_desc}"
                print_log("INFO", "Forense completado. No hay correos públicos.")
                
        except Exception as e:
            datos_abuso = f"Error Whois: {e}"

        asunto = f"ALERTA EMERGENCIA: Conexión Maliciosa ({ip_dst})"
        cuerpo = f"Tráfico detectado hacia lista negra.\nIP: {ip_dst}\nFecha: {hora_actual}\n\n=== REPORTE FORENSE ===\n{datos_abuso}"
        enviar_correo(asunto, cuerpo)

def procesar_paquete(packet):
    if IP in packet and Ether in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        mac_src = packet[Ether].src.lower()

        if ip_src == "127.0.0.1" or ip_src.startswith("169.254."):
            return

        # ==========================================
        # SE INCLUYE EL RANGO DE LA RED (148.211.x.x)
        # ==========================================
        is_local_ip = (
            ip_src.startswith("192.168.") or 
            ip_src.startswith("10.") or 
            ip_src.startswith("172.") or 
            ip_src.startswith("148.211.")
        )

        if is_local_ip:
            if ip_src not in whitelist['ips'] or mac_src not in whitelist['macs']:
                manejar_intruso(ip_src, mac_src)

        if ip_dst in blacklist:
            threading.Thread(target=automatizacion_forense, args=(ip_dst,)).start()

        hora_actual = datetime.now().strftime("%H:%M:%S")
        record = None

        if packet.haslayer(DNSQR) and packet[DNSQR].qname:
            dominio = packet[DNSQR].qname.decode('utf-8').strip('.')
            record = {'hora': hora_actual, 'origen': ip_src, 'destino': dominio, 'protocolo': 'DNS', 'mac_origen': mac_src}

        elif packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if "Host:" in payload:
                    for linea in payload.split('\r\n'):
                        if linea.startswith("Host:"):
                            dominio_http = linea.split(" ")[1].strip()
                            record = {'hora': hora_actual, 'origen': ip_src, 'destino': dominio_http, 'protocolo': 'HTTP', 'mac_origen': mac_src}
            except:
                pass
        
        if record:
            traffic_log.append(record)
            socketio.emit('trafico', record)
            print_log("TRAFFIC", f"{record['origen']} --> {record['destino']} [{record['protocolo']}]")

def iniciar_sniffer():
    print_log("INFO", "Motor de captura de paquetes (Scapy) iniciado.")
    sniff(prn=procesar_paquete, store=False)

def abrir_navegador():
    print_log("INFO", "Abriendo interfaz web en el navegador...")
    webbrowser.open_new('http://127.0.0.1:5000')

# ==========================================
# RUTAS API
# ==========================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/whitelist/add', methods=['POST'])
def add_to_whitelist():
    data = request.json
    ip = data.get('ip')
    mac = data.get('mac')
    if ip and ip not in whitelist['ips']:
        whitelist['ips'].append(ip)
    if mac and mac not in whitelist['macs']:
        whitelist['macs'].append(mac)
    guardar_whitelist()
    print_log("INFO", f"IP {ip} añadida a lista blanca desde la UI.")
    return {"status": "success", "message": f"{ip} añadido a la lista blanca."}

@app.route('/api/block', methods=['POST'])
def block_ip():
    ip = request.json.get('ip')
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
        print_log("ALERT", f"IP {ip} bloqueada exitosamente en el Firewall (iptables).")
        return {"status": "success", "message": f"{ip} bloqueada en el firewall."}
    except Exception as e:
        print_log("ALERT", f"Fallo al bloquear IP: {e}")
        return {"status": "error", "message": str(e)}, 500

@app.route('/api/scan/virustotal', methods=['POST'])
def scan_virustotal():
    ip = request.json.get('ip')
    if not VT_API_KEY:
        return {"status": "error", "message": "API Key de VirusTotal no configurada en el archivo .env"}, 500

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}

    try:
        print_log("INFO", f"Consultando VirusTotal para la IP: {ip}...")
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            if malicious > 0 or suspicious > 0:
                msg = f"¡ALERTA! {malicious} motores la marcan como maliciosa y {suspicious} como sospechosa."
            else:
                msg = "IP Limpia: Ningún motor detectó amenazas en esta IP."
                
            return {"status": "success", "message": msg, "stats": stats}
        else:
            return {"status": "error", "message": f"Error consultando VirusTotal: Código {response.status_code}"}, 500
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500

@app.route('/api/export/csv')
def export_csv():
    si = io.StringIO()
    writer = csv.DictWriter(si, fieldnames=['hora', 'origen', 'mac_origen', 'destino', 'protocolo'])
    writer.writeheader()
    writer.writerows(traffic_log)
    
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename=ids_report_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    output.headers["Content-type"] = "text/csv"
    print_log("INFO", "Usuario descargó el reporte CSV.")
    return output

if __name__ == '__main__':
    os.system('clear')
    print(f"\n{NColor.WHITE}{NColor.BOLD}=== N_IDS V2.0 SYSTEM INITIALIZATION ==={NColor.RESET}\n")
    
    cargar_listas()
    hilo_sniff = threading.Thread(target=iniciar_sniffer)
    hilo_sniff.daemon = True
    hilo_sniff.start()
    
    print_log("INFO", "Servidor GUI y WebSockets en línea (http://127.0.0.1:5000)")
    Timer(1.5, abrir_navegador).start()
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)