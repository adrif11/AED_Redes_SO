# --------------------------------------------------------------------------------
# SEÇÃO 1: IMPORTAÇÕES
# --------------------------------------------------------------------------------
import socket
import threading
import ipaddress
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import platform
from scapy.all import ARP, Ether, srp

try:
    from puresnmp import get as puresnmp_get
    from puresnmp.exc import SnmpError, Timeout as PureSnmpTimeout
    PURESNMP_DISPONIVEL = True
except ImportError:
    print("[ERRO FATAL PureSNMP] Biblioteca 'puresnmp' não encontrada!")
    print("Execute no terminal (com o ambiente virtual ativo): pip install puresnmp")
    print("A funcionalidade SNMP não estará disponível.")
    PURESNMP_DISPONIVEL = False

# --------------------------------------------------------------------------------
# SEÇÃO 2: CONFIGURAÇÕES GLOBAIS
# --------------------------------------------------------------------------------
PORTA_SERVIDOR = 35640
MAX_THREADS_SCAN_PING = 50
TIMEOUT_PING_SEGUNDOS = 2.0
USAR_ARP_SCAN = True

SNMP_COMMUNITY = 'public'
SNMP_PORTA = 161
SNMP_TIMEOUT_S = 1.0
OID_SYSNAME_STR = '1.3.6.1.2.1.1.5.0'

# --------------------------------------------------------------------------------
# SEÇÃO 3: FUNÇÕES DE SCAN
# --------------------------------------------------------------------------------

def obter_sysname_via_puresnmp(ip_alvo):
    """ Tenta obter o sysName de um host via SNMP usando a biblioteca PureSNMP. """
    if not PURESNMP_DISPONIVEL:
        return None

    try:
        valor_em_bytes = puresnmp_get(
            str(ip_alvo), SNMP_COMMUNITY, OID_SYSNAME_STR,
            port=SNMP_PORTA, timeout=int(SNMP_TIMEOUT_S)
        )
        if valor_em_bytes is not None:
            try:
                return valor_em_bytes.decode('utf-8', errors='replace').strip()
            except UnicodeDecodeError:
                return valor_em_bytes.decode('latin-1', errors='replace').strip()
        return None
    except (PureSnmpTimeout, SnmpError, Exception):
        return None

def testar_host_com_ping(ip_host_para_testar):
    ip_texto = str(ip_host_para_testar)
    if platform.system() == "Windows":
        comando = ['ping', '-n', '1', '-w', str(int(TIMEOUT_PING_SEGUNDOS * 1000)), ip_texto]
    else: # Linux
        comando = ['ping', '-c', '1', '-w', str(int(TIMEOUT_PING_SEGUNDOS)), ip_texto]
    try:
        resultado = subprocess.run(
            comando, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=TIMEOUT_PING_SEGUNDOS + 1.0)
        return resultado.returncode == 0
    except Exception:
        return False

def scan_arp_rede_local(objeto_rede_alvo):
    ips_ativos_via_arp = []
    try:
        pacote_arp_requisicao = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(objeto_rede_alvo))
        lista_pacotes_respondidos, _ = srp(pacote_arp_requisicao, timeout=1, verbose=False)
        if lista_pacotes_respondidos:
            for _,p_resp in lista_pacotes_respondidos: ips_ativos_via_arp.append(p_resp.psrc)
    except Exception as e:
        print(f"  [ARP ERRO INTERNO] Falha durante o scan ARP (requer sudo): {e}.")
    return list(set(ips_ativos_via_arp))

def scan_ping_em_paralelo(objeto_rede_alvo):
    ips_ativos_via_ping = []
    lista_ips_para_testar = list(objeto_rede_alvo.hosts())
    if not lista_ips_para_testar: return []
    with ThreadPoolExecutor(max_workers=MAX_THREADS_SCAN_PING) as executor:
        mapa = {executor.submit(testar_host_com_ping, ip): ip for ip in lista_ips_para_testar}
        for fut in as_completed(mapa):
            try:
                if fut.result(): ips_ativos_via_ping.append(str(mapa[fut]))
            except: pass
    return list(set(ips_ativos_via_ping))

def executar_scan_completo_na_rede(objeto_rede_alvo):
    ativos = set()
    if USAR_ARP_SCAN:
        print(f"[SCAN INFO] Fase 1: Scan ARP para {objeto_rede_alvo}...")
        ips_arp = scan_arp_rede_local(objeto_rede_alvo)
        for ip_arp_add in ips_arp: ativos.add(ip_arp_add)
        print(f"[SCAN INFO] Fase 1 (ARP) concluída. {len(ips_arp)} hosts via ARP (total no conjunto: {len(ativos)}).")
    else: print("[SCAN INFO] Fase 1: Scan ARP desabilitado.")

    print(f"[SCAN INFO] Fase 2: Scan Ping para {objeto_rede_alvo}...")
    ips_ping = scan_ping_em_paralelo(objeto_rede_alvo)
    for ip_ping_add in ips_ping: ativos.add(ip_ping_add)
    print(f"[SCAN INFO] Fase 2 (Ping) concluída. {len(ips_ping)} hosts via Ping (total no conjunto: {len(ativos)}).")

    total = len(ativos)
    if total > 0: print(f"[SCAN INFO] Scan total finalizado! {total} hosts ativos únicos. :)")
    else: print(f"[SCAN INFO] Scan total finalizado. Nenhum host ativo. :(")
    return list(ativos)

def gerenciar_conexao_cliente(sock_cli, end_cli):
    print(f"[CONEXÃO] Cliente {end_cli} conectou-se!")
    try:
        while True:
            dados = sock_cli.recv(1024).decode('utf-8').strip()
            if not dados: print(f"[CONEXÃO] Cliente {end_cli} desconectou."); break
            print(f"[CLIENTE {end_cli}] Requisição: '{dados}'")

            if dados.startswith("GET /"):
                http_response = "HTTP/1.1 200 OK\n\nServidor de Scan de Rede.\n"
                sock_cli.sendall(http_response.encode('utf-8'))
                break

            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$', dados):
                sock_cli.sendall(b"ERRO: Formato CIDR invalido. Use IP/prefixo.\n"); continue
            try:
                rede = ipaddress.IPv4Network(dados, strict=False)
                sock_cli.sendall(f"INFO: Scan iniciado para {rede}. Aguarde...\n".encode('utf-8'))
                ips_ativos = executar_scan_completo_na_rede(rede)
                if ips_ativos:
                    sock_cli.sendall(f"RESULTADO: {len(ips_ativos)} host(s) ativo(s):\n".encode('utf-8'))
                    for ip in ips_ativos:
                        sysname = obter_sysname_via_puresnmp(ip)
                        linha = f"{ip} {sysname}\n" if sysname else f"{ip}\n"
                        sock_cli.sendall(linha.encode('utf-8'))
                else: sock_cli.sendall(b"RESULTADO: Nenhum host ativo encontrado.\n")
                sock_cli.sendall(b"INFO: Scan para esta rede concluido.\n")
            except ValueError as e:
                sock_cli.sendall(f"ERRO: Endereco de rede invalido '{dados}'. {e}\n".encode('utf-8'))
    except ConnectionResetError: print(f"[CONEXÃO] Cliente {end_cli} resetou.")
    except Exception as e: print(f"[ERRO] Cliente {end_cli}: {e}")
    finally: print(f"[CONEXÃO] Encerrando com {end_cli}."); sock_cli.close()

def iniciar_servidor_principal():
    sock_serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock_serv.bind(('0.0.0.0', PORTA_SERVIDOR))
        print(f"[SERVIDOR] Online na porta {PORTA_SERVIDOR}.")
    except OSError as e: print(f"[SERVIDOR ERRO] Bind falhou: {e}"); return
    sock_serv.listen(5)
    print(f"[SERVIDOR] Aguardando conexoes...")
    try:
        while True:
            cli_sock, cli_end = sock_serv.accept()
            threading.Thread(target=gerenciar_conexao_cliente, args=(cli_sock, cli_end), daemon=True).start()
    except KeyboardInterrupt: print("\n[SERVIDOR] Desligando...")
    except Exception as e: print(f"[SERVIDOR ERRO FATAL] {e}")
    finally: sock_serv.close()

if __name__ == "__main__":
    if platform.system() != "Linux":
        print("[AVISO] Este script é otimizado para Linux (onde o Scapy com ARP funciona melhor com sudo).")
    
    if PURESNMP_DISPONIVEL:
        print("[INFO] Iniciando servidor com funcionalidade SNMP (via PureSNMP).")
    else:
        print("[AVISO] Iniciando servidor SEM funcionalidade SNMP (PureSNMP não encontrado).")
    
    iniciar_servidor_principal()
