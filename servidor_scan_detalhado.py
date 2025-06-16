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
MAX_THREADS_SCAN = 100 # Aumentado para um scan mais rápido
TIMEOUT_PING_SEGUNDOS = 1.0 # 1 segundo é um bom equilíbrio
USAR_ARP_SCAN = True # Mantemos o ARP para descoberta rápida em redes locais

# Configurações para o PureSNMP
SNMP_COMMUNITY = 'public'
SNMP_PORTA = 161
SNMP_TIMEOUT_S = 1.0
OID_SYSNAME_STR = '1.3.6.1.2.1.1.5.0'
OID_SYSDESCR_STR = '1.3.6.1.2.1.1.1.0' # Adicionamos o OID do sysDescr

# --------------------------------------------------------------------------------
# SEÇÃO 3: FUNÇÕES DE VERIFICAÇÃO DE HOST
# --------------------------------------------------------------------------------

def obter_info_snmp(ip_alvo):
    """
    Tenta obter o sysName e/ou sysDescr de um host via PureSNMP.
    Retorna um dicionário com as informações encontradas.
    """
    if not PURESNMP_DISPONIVEL:
        return None

    resultados_snmp = {}
    # Tenta obter o sysName
    try:
        valor_bytes = puresnmp_get(str(ip_alvo), SNMP_COMMUNITY, OID_SYSNAME_STR, port=SNMP_PORTA, timeout=int(SNMP_TIMEOUT_S))
        if valor_bytes:
            resultados_snmp['sysName'] = valor_bytes.decode('utf-8', errors='replace').strip()
    except (PureSnmpTimeout, SnmpError, Exception):
        pass # Ignora erros se o sysName não for encontrado

    # Tenta obter o sysDescr (descrição do sistema)
    try:
        valor_bytes = puresnmp_get(str(ip_alvo), SNMP_COMMUNITY, OID_SYSDESCR_STR, port=SNMP_PORTA, timeout=int(SNMP_TIMEOUT_S))
        if valor_bytes:
            # Limita a descrição para não poluir a saída
            descricao = valor_bytes.decode('utf-8', errors='replace').strip().replace('\n', ' ').replace('\r', '')
            resultados_snmp['sysDescr'] = (descricao[:70] + '...') if len(descricao) > 70 else descricao
    except (PureSnmpTimeout, SnmpError, Exception):
        pass # Ignora erros se o sysDescr não for encontrado

    return resultados_snmp if resultados_snmp else None

def testar_host_com_ping(ip_host_para_testar):
    """ Verifica se um host responde ao ping. Retorna True ou False. """
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

# --------------------------------------------------------------------------------
# SEÇÃO 4: FUNÇÕES DE SCAN DA REDE
# --------------------------------------------------------------------------------

def scan_arp_rede_local(objeto_rede_alvo):
    """ Usa ARP para uma descoberta rápida de hosts na rede local. """
    ips_ativos_via_arp = set()
    try:
        pacote_arp_requisicao = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(objeto_rede_alvo))
        lista_pacotes_respondidos, _ = srp(pacote_arp_requisicao, timeout=2, verbose=False)
        if lista_pacotes_respondidos:
            for _,p_resp in lista_pacotes_respondidos:
                ips_ativos_via_arp.add(p_resp.psrc)
    except Exception as e:
        # Não imprime o erro no console para uma saída mais limpa na apresentação
        pass
    return list(ips_ativos_via_arp)

def verificar_host_individual(ip):
    """
    Verifica um único host com Ping e depois com SNMP, retornando seu status.
    """
    ip_str = str(ip)
    # Primeiro, verifica se o host está ativo com Ping
    if testar_host_com_ping(ip_str):
        # Se respondeu ao ping, tenta obter informações SNMP
        info_snmp = obter_info_snmp(ip_str)
        if info_snmp:
            # Monta a resposta SNMP, priorizando o sysName
            nome_snmp = info_snmp.get('sysName', info_snmp.get('sysDescr', ''))
            return (ip_str, f'Ativo com SNMP: {nome_snmp}')
        else:
            return (ip_str, 'Ativo (Ping OK, sem resposta SNMP)')
    else:
        return (ip_str, 'Sem resposta ao Ping')

def executar_scan_completo_na_rede(objeto_rede_alvo):
    """
    Orquestra o scan da rede, usando ARP para descoberta e depois verificando
    cada host com Ping e SNMP em paralelo.
    """
    print(f"[SCAN INFO] Analisando a rede: {objeto_rede_alvo}...")
    todos_os_hosts = list(objeto_rede_alvo.hosts())

    # Opcional: usar ARP para focar o scan apenas em hosts que sabemos que existem
    if USAR_ARP_SCAN:
        print(f"[SCAN INFO] Fase 1: Descoberta rápida com ARP...")
        hosts_arp = scan_arp_rede_local(objeto_rede_alvo)
        if hosts_arp:
            print(f"[SCAN INFO] Fase 1 (ARP) encontrou {len(hosts_arp)} hosts. Verificando-os...")
            # Adiciona os hosts do ARP a lista principal, evitando duplicatas
            todos_os_hosts = list(set(todos_os_hosts) | set(map(str, hosts_arp)))

    print(f"[SCAN INFO] Fase 2: Verificando {len(todos_os_hosts)} hosts com Ping e SNMP em paralelo...")
    
    resultados = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS_SCAN) as executor:
        # Agenda a verificação completa (ping + snmp) para cada host
        mapa_de_tarefas = {executor.submit(verificar_host_individual, ip): ip for ip in todos_os_hosts}
        
        for tarefa_concluida in as_completed(mapa_de_tarefas):
            try:
                resultado = tarefa_concluida.result()
                if resultado:
                    resultados.append(resultado)
            except Exception:
                pass # Ignora falhas em threads individuais

    # Ordena os resultados pelo endereço IP
    resultados.sort(key=lambda x: ipaddress.ip_address(x[0]))
    return resultados

# --------------------------------------------------------------------------------
# SEÇÃO 5: LÓGICA DO SERVIDOR
# --------------------------------------------------------------------------------

def gerenciar_conexao_cliente(sock_cli, end_cli):
    print(f"[CONEXÃO] Cliente {end_cli} conectou-se.")
    try:
        dados = sock_cli.recv(1024).decode('utf-8').strip()
        if not dados:
            print(f"[CONEXÃO] Cliente {end_cli} desconectou sem enviar dados.")
            return

        print(f"[CLIENTE {end_cli}] Requisição: '{dados}'")

        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}\/\d{1,32}$', dados):
            sock_cli.sendall(b"ERRO: Formato CIDR invalido. Use IP/prefixo (ex: 192.168.1.0/24).\n")
            return

        try:
            rede = ipaddress.IPv4Network(dados, strict=False)
            sock_cli.sendall(f"INFO: Scan iniciado para {rede}. Isso pode levar um tempo...\n".encode('utf-8'))
            
            resultados_scan = executar_scan_completo_na_rede(rede)
            
            if resultados_scan:
                sock_cli.sendall(f"\n--- Relatorio de Scan para {rede} ---\n".encode('utf-8'))
                for ip, status in resultados_scan:
                    linha = f"{ip:<18} | {status}\n" # Formata para alinhar as colunas
                    sock_cli.sendall(linha.encode('utf-8'))
            else:
                sock_cli.sendall(b"INFO: Nenhum host encontrado na faixa especificada.\n")

        except ValueError as e:
            sock_cli.sendall(f"ERRO: Endereco de rede invalido '{dados}'. {e}\n".encode('utf-8'))

    except Exception as e:
        print(f"[ERRO] Erro com o cliente {end_cli}: {e}")
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
            # Uma thread por cliente, como no código original.
            threading.Thread(target=gerenciar_conexao_cliente, args=(cli_sock, cli_end), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[SERVIDOR] Desligando...")
    finally:
        sock_serv.close()

if __name__ == "__main__":
    print("--- Servidor de Scan de Ativos em Rede ---")
    if not PURESNMP_DISPONIVEL:
        print("[AVISO] Biblioteca 'puresnmp' não encontrada. A funcionalidade SNMP não estará disponível.")
    iniciar_servidor_principal()
