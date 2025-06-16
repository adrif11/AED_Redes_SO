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
    PURESNMP_DISPONIVEL = False

# --------------------------------------------------------------------------------
# SEÇÃO 2: CONFIGURAÇÕES GLOBAIS
# --------------------------------------------------------------------------------
PORTA_SERVIDOR = 35640
MAX_THREADS_SCAN = 100
TIMEOUT_PING_SEGUNDOS = 1.0
USAR_ARP_SCAN = True

SNMP_COMMUNITY = 'public'
SNMP_PORTA = 161
SNMP_TIMEOUT_S = 1.0
OID_SYSNAME_STR = '1.3.6.1.2.1.1.5.0'
OID_SYSDESCR_STR = '1.3.6.1.2.1.1.1.0'

# --------------------------------------------------------------------------------
# SEÇÃO 3: FUNÇÕES DE VERIFICAÇÃO DE HOST
# --------------------------------------------------------------------------------

def obter_info_snmp(ip_alvo):
    if not PURESNMP_DISPONIVEL: return None
    resultados_snmp = {}
    try:
        valor_bytes = puresnmp_get(str(ip_alvo), SNMP_COMMUNITY, OID_SYSNAME_STR, port=SNMP_PORTA, timeout=int(SNMP_TIMEOUT_S))
        if valor_bytes: resultados_snmp['sysName'] = valor_bytes.decode('utf-8', errors='replace').strip()
    except: pass
    if 'sysName' not in resultados_snmp:
        try:
            valor_bytes = puresnmp_get(str(ip_alvo), SNMP_COMMUNITY, OID_SYSDESCR_STR, port=SNMP_PORTA, timeout=int(SNMP_TIMEOUT_S))
            if valor_bytes:
                descricao = valor_bytes.decode('utf-8', errors='replace').strip().replace('\n', ' ').replace('\r', '')
                resultados_snmp['sysDescr'] = (descricao[:70] + '...') if len(descricao) > 70 else descricao
        except: pass
    return resultados_snmp if resultados_snmp else None

def testar_host_com_ping(ip_host_para_testar):
    ip_texto = str(ip_host_para_testar)
    if platform.system() == "Windows":
        comando = ['ping', '-n', '1', '-w', str(int(TIMEOUT_PING_SEGUNDOS * 1000)), ip_texto]
    else: # Linux
        comando = ['ping', '-c', '1', '-w', str(int(TIMEOUT_PING_SEGUNDOS)), ip_texto]
    try:
        resultado = subprocess.run(
            comando, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=TIMEOUT_PING_SEGUNDOS + 1.0)
        return resultado.returncode == 0
    except Exception:
        return False

# --------------------------------------------------------------------------------
# SEÇÃO 4: FUNÇÕES DE SCAN DA REDE
# --------------------------------------------------------------------------------

def scan_arp_rede_local(objeto_rede_alvo):
    ips_ativos_via_arp = set()
    try:
        pacote_arp_requisicao = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(objeto_rede_alvo))
        lista_pacotes_respondidos, _ = srp(pacote_arp_requisicao, timeout=2, verbose=False)
        if lista_pacotes_respondidos:
            for _,p_resp in lista_pacotes_respondidos: ips_ativos_via_arp.add(p_resp.psrc)
    except Exception: pass
    return list(ips_ativos_via_arp)

def verificar_host_individual(ip):
    ip_str = str(ip)
    if testar_host_com_ping(ip_str):
        info_snmp = obter_info_snmp(ip_str)
        if info_snmp:
            nome_snmp = info_snmp.get('sysName', info_snmp.get('sysDescr', ''))
            return (ip_str, f'Ativo com SNMP: {nome_snmp}')
        else:
            return (ip_str, 'Ativo (Ping OK, sem resposta SNMP)')
    else:
        return (ip_str, 'Sem resposta ao Ping')

def executar_scan_completo_na_rede(objeto_rede_alvo):
    print(f"[SCAN INFO] Analisando a rede: {objeto_rede_alvo}...")
    hosts_para_verificar = set(map(str, objeto_rede_alvo.hosts()))
    if USAR_ARP_SCAN:
        print(f"[SCAN INFO] Fase 1: Descoberta rápida com ARP...")
        hosts_arp = scan_arp_rede_local(objeto_rede_alvo)
        if hosts_arp:
            print(f"[SCAN INFO] Fase 1 (ARP) encontrou {len(hosts_arp)} hosts.")
            hosts_para_verificar.update(hosts_arp)

    print(f"[SCAN INFO] Fase 2: Verificando {len(hosts_para_verificar)} hosts com Ping e SNMP em paralelo...")
    resultados = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS_SCAN) as executor:
        mapa_de_tarefas = {executor.submit(verificar_host_individual, ip): ip for ip in hosts_para_verificar}
        for tarefa_concluida in as_completed(mapa_de_tarefas):
            try:
                resultado = tarefa_concluida.result()
                if resultado: resultados.append(resultado)
            except: pass
    resultados.sort(key=lambda x: ipaddress.ip_address(x[0]))
    return resultados

# --------------------------------------------------------------------------------
# SEÇÃO 5: LÓGICA DO SERVIDOR
# --------------------------------------------------------------------------------

def gerenciar_conexao_cliente(sock_cli, end_cli):
    """
    Gerencia a conexão com um cliente. Esta versão é adaptada para ler
    uma linha completa de cada vez, tornando-a compatível com clientes
    de terminal como Telnet e netcat.
    """
    print(f"[CONEXÃO] Cliente {end_cli} conectou-se.")
    
    try:
        arquivo_cliente = sock_cli.makefile('rw', encoding='utf-8', newline='\n')
        linha_recebida = arquivo_cliente.readline().strip()

        if not linha_recebida:
            print(f"[CONEXÃO] Cliente {end_cli} desconectou sem enviar dados.")
            return

        print(f"[CLIENTE {end_cli}] Requisição: '{linha_recebida}'")


        if linha_recebida.startswith("GET /"):
            arquivo_cliente.write("HTTP/1.1 200 OK\n\nServidor de Scan. Use um cliente Telnet ou netcat.\n")
            arquivo_cliente.flush() # Garante que a mensagem seja enviada
            return

        # 2. VALIDAR E PROCESSAR A REQUISIÇÃO
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}\/\d{1,32}$', linha_recebida):
            arquivo_cliente.write("ERRO: Formato CIDR invalido. Use IP/prefixo (ex: 192.168.1.0/24).\n")
            arquivo_cliente.flush()
            return
        
        try:
            rede = ipaddress.IPv4Network(linha_recebida, strict=False)
            arquivo_cliente.write(f"INFO: Scan iniciado para {rede}. Aguarde...\n")
            arquivo_cliente.flush()
            
            resultados_scan = executar_scan_completo_na_rede(rede)
            
            if resultados_scan:
                arquivo_cliente.write(f"\n--- Relatorio de Scan para {rede} ---\n")
                for ip, status in resultados_scan:

                    linha = f"{ip:<18} | {status}\n"
                    arquivo_cliente.write(linha)
            else:
                arquivo_cliente.write("INFO: Nenhum host encontrado na faixa especificada.\n")

        except ValueError as e:
            arquivo_cliente.write(f"ERRO: Endereco de rede invalido '{linha_recebida}'. {e}\n")
        
        finally:
            arquivo_cliente.flush()

    except Exception as e:
        print(f"[ERRO] Erro inesperado com o cliente {end_cli}: {e}")
    finally:
        print(f"[CONEXÃO] Encerrando com {end_cli}.")
        sock_cli.close()


def iniciar_servidor_principal():
    sock_serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock_serv.bind(('0.0.0.0', PORTA_SERVIDOR))
        print(f"[SERVIDOR] Online na porta {PORTA_SERVIDOR}.")
    except OSError as e:
        print(f"[SERVIDOR ERRO] Bind falhou: {e}"); return
    sock_serv.listen(5)
    print(f"[SERVIDOR] Aguardando conexoes...")
    try:
        while True:
            cli_sock, cli_end = sock_serv.accept()
            threading.Thread(target=gerenciar_conexao_cliente, args=(cli_sock, cli_end), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[SERVIDOR] Desligando...")
    finally:
        sock_serv.close()

if __name__ == "__main__":
    print("--- Servidor de Scan de Ativos em Rede ---")
    if PURESNMP_DISPONIVEL:
        print("[INFO] Funcionalidade SNMP ativa (via PureSNMP).")
    else:
        print("[AVISO] Biblioteca 'puresnmp' não encontrada. Funcionalidade SNMP desativada.")
    iniciar_servidor_principal()
