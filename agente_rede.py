"""RTI Segurança - agente local de descoberta de dispositivos.
Use somente em redes próprias ou com autorização.
Executar: python agente_rede.py
Depois abra o site e clique em Escanear rede.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from concurrent.futures import ThreadPoolExecutor
import subprocess, socket, platform, re, json, ipaddress, sys, time

IS_WIN = platform.system().lower().startswith('win')

# Base local simples. O fabricante também pode ser inferido pelo nome do equipamento.
# O modelo exato só é exibido quando há evidência suficiente; caso contrário, não é inventado.
OUI = {
    '30:05:5C': 'Brother Industries',
    '00:1B:A9': 'Brother Industries',
    '00:80:77': 'Brother Industries',
    '00:1E:58': 'D-Link',
    '00:1C:F0': 'D-Link',
    'C0:4A:00': 'TP-Link',
    '50:C7:BF': 'TP-Link',
    'F4:F2:6D': 'TP-Link',
    '24:A4:3C': 'Ubiquiti',
    'FC:EC:DA': 'Ubiquiti',
    '78:8A:20': 'Ubiquiti',
    '44:19:B6': 'Hikvision',
    'C0:56:E3': 'Hikvision',
    'BC:AD:28': 'Hikvision',
    '3C:EF:8C': 'Dahua',
    'A0:BD:1D': 'Dahua',
    'E0:50:8B': 'Dahua',
    '00:1A:3F': 'Intelbras',
    'F8:E7:1E': 'Intelbras',
}

def local_ip():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try: s.connect(('8.8.8.8',80)); return s.getsockname()[0]
    except: return '192.168.1.1'
    finally: s.close()

def ping(ip):
    cmd=['ping','-n' if IS_WIN else '-c','1','-w' if IS_WIN else '-W','350' if IS_WIN else '1',str(ip)]
    try: return subprocess.run(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2).returncode==0
    except: return False

def arp_map():
    try: out=subprocess.check_output(['arp','-a'],text=True,errors='ignore')
    except: return {}
    found={}
    for line in out.splitlines():
        m=re.search(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})',line)
        if m: found[m.group(1)]=m.group(2).upper().replace('-',':')
    return found

def identify(hostname, mac, ip):
    h=(hostname or '').upper(); m=(mac or '').upper()
    brand=next((vendor for prefix,vendor in OUI.items() if m.startswith(prefix)), '')
    kind='Dispositivo de rede'; model=''
    # Heurísticas conservadoras pelo hostname; não inventam modelo exato.
    if h.startswith('BRN') or 'BROTHER' in h:
        brand=brand or 'Brother Industries'; kind='Impressora'
    elif any(x in h for x in ['HIKVISION','HIK','DS-2CD','DS-2DE']):
        brand=brand or 'Hikvision'; kind='Câmera/NVR'
    elif any(x in h for x in ['DAHUA','IPC-','NVR','XVR']):
        brand=brand or 'Dahua'; kind='Câmera/NVR'
    elif 'INTELBRAS' in h or h.startswith('VIP'):
        brand=brand or 'Intelbras'; kind='Câmera/NVR'
    elif any(x in h for x in ['UBNT','UAP','UNIFI']):
        brand=brand or 'Ubiquiti'; kind='Access Point/Rede'
    elif any(x in h for x in ['ROUTER','ROTEADOR','GATEWAY']): kind='Roteador/Gateway'
    elif any(x in h for x in ['DESKTOP','NOTEBOOK','LAPTOP','PC-']): kind='Computador'
    if ip.endswith('.1') and not hostname: kind='Roteador/Gateway'
    # Alguns hostnames carregam o identificador/modelo; só reaproveitamos quando explícito.
    mm=re.search(r'\b(DS-[A-Z0-9-]{4,}|IPC-[A-Z0-9-]{3,}|VIP[-A-Z0-9]{3,}|NVR[-A-Z0-9]{3,}|XVR[-A-Z0-9]{3,})\b', h)
    if mm: model=mm.group(1)
    return brand or 'Não identificado', model or kind

def scan():
    lip=local_ip(); net=ipaddress.ip_network(lip+'/24',strict=False)
    hosts=[str(x) for x in net.hosts()]
    with ThreadPoolExecutor(max_workers=48) as ex:
        online=[ip for ip,ok in zip(hosts,ex.map(ping,hosts)) if ok]
    macs=arp_map(); devices=[]
    for ip in online:
        try: name=socket.gethostbyaddr(ip)[0]
        except: name=''
        mac=macs.get(ip,''); brand, model_type=identify(name,mac,ip)
        devices.append({'ip':ip,'hostname':name,'brand':brand,'model_type':model_type,'mac':mac})
    return {'network':str(net),'devices':devices}

def conflict_test():
    """Procura IPs cujo MAC muda entre amostras ARP sucessivas.
    É um indicador prático de conflito; não altera a rede.
    """
    lip=local_ip(); net=ipaddress.ip_network(lip+'/24',strict=False)
    seen={}
    # Várias rodadas aumentam a chance de observar dois aparelhos respondendo pelo mesmo IP.
    for _ in range(4):
        hosts=[str(x) for x in net.hosts()]
        with ThreadPoolExecutor(max_workers=48) as ex:
            list(ex.map(ping,hosts))
        for ip,mac in arp_map().items():
            if ipaddress.ip_address(ip) in net:
                seen.setdefault(ip,set()).add(mac)
        time.sleep(0.35)
    conflicts=[]
    for ip,macs in sorted(seen.items(), key=lambda x: tuple(map(int,x[0].split('.')))):
        if len(macs)>1:
            conflicts.append({'ip':ip,'macs':sorted(macs),'status':'Conflito detectado'})
    return {'network':str(net),'conflicts':conflicts,'checked':len(seen)}

def speed_test():
    """Executa speedtest-cli quando instalado e devolve Mbps/ping."""
    try:
        cmd=[sys.executable,'-m','speedtest','--simple','--secure']
        out=subprocess.check_output(cmd,text=True,errors='ignore',stderr=subprocess.STDOUT,timeout=90)
        pm=re.search(r'Ping:\s*([0-9.]+)\s*ms',out,re.I)
        dm=re.search(r'Download:\s*([0-9.]+)\s*Mbit/s',out,re.I)
        um=re.search(r'Upload:\s*([0-9.]+)\s*Mbit/s',out,re.I)
        if not (pm and dm and um): raise RuntimeError('Resultado do teste não reconhecido')
        return {'ping':float(pm.group(1)),'download':float(dm.group(1)),'upload':float(um.group(1)),'server':'Speedtest automático'}
    except subprocess.CalledProcessError as e:
        txt=e.output or ''
        if 'No module named speedtest' in txt:
            raise RuntimeError('speedtest-cli não instalado')
        raise RuntimeError('Falha ao executar teste de velocidade')
    except Exception as e:
        if 'No module named' in str(e): raise RuntimeError('speedtest-cli não instalado')
        raise

class H(BaseHTTPRequestHandler):
    def _headers(self,code=200):
        self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Access-Control-Allow-Origin','*'); self.end_headers()
    def do_GET(self):
        if self.path=='/scan':
            self._headers(); self.wfile.write(json.dumps(scan(),ensure_ascii=False).encode()); return
        if self.path=='/conflicts':
            self._headers(); self.wfile.write(json.dumps(conflict_test(),ensure_ascii=False).encode()); return
        if self.path=='/speed':
            try:
                data=speed_test(); self._headers(); self.wfile.write(json.dumps(data,ensure_ascii=False).encode())
            except Exception as e:
                self._headers(500); self.wfile.write(json.dumps({'error':str(e)},ensure_ascii=False).encode())
            return
        self._headers(404); self.wfile.write(b'{}')
    def log_message(self,*args): pass

print('RTI Segurança - Agente de Rede')
print('Ativo em http://127.0.0.1:8765')
print('Scanner, detector de conflito de IP e teste de velocidade disponíveis.')
print('Para o teste de velocidade, instale uma vez: pip install speedtest-cli')
print('Deixe esta janela aberta enquanto usar o scanner.')
HTTPServer(('127.0.0.1',8765),H).serve_forever()
