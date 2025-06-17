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

# Configurações para o PureSNMP
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
            comando, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=TIMEOUT_PING_SEGUNDOS + 1.0)
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
    Gerencia a conexão com um cliente de forma persistente, lendo múltiplas
    requisições até que o cliente desconecte ou envie 'sair'.
    """
    print(f"[CONEXÃO] Cliente {end_cli} conectou-se.")
    
    try:
        # Transforma o socket em um objeto tipo "arquivo" para ler e escrever linhas.
        arquivo_cliente = sock_cli.makefile('rw', encoding='utf-8', newline='\n')
        arquivo_cliente.write("--- Bem-vindo ao Servidor de Scan de Rede ---\n")
        arquivo_cliente.write("Digite um CIDR (ex: 192.168.1.0/24) ou 'sair' para fechar.\n")
        arquivo_cliente.flush()

        # **** MUDANÇA PRINCIPAL AQUI: LOOP WHILE TRUE ****
        # Este loop mantém a conexão aberta, esperando por novos comandos.
        while True:
            # .readline() espera até que o cliente envie uma linha terminada com Enter.
            linha_recebida = arquivo_cliente.readline()
            if not linha_recebida:
                # Se readline() retorna uma string vazia, o cliente fechou a conexão.
                print(f"[CONEXÃO] Cliente {end_cli} desconectou.")
                break # Sai do loop while
            
            # Remove espaços em branco e caracteres de nova linha da entrada
            comando_cliente = linha_recebida.strip()
            print(f"[CLIENTE {end_cli}] Requisição: '{comando_cliente}'")

            # Verifica se o cliente quer sair
            if comando_cliente.lower() in ['sair', 'exit', 'quit']:
                arquivo_cliente.write("Até logo!\n")
                arquivo_cliente.flush()
                break # Sai do loop while

            # Valida o formato CIDR
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}\/\d{1,32}$', comando_cliente):
                arquivo_cliente.write("ERRO: Formato CIDR invalido. Tente novamente.\n")
                arquivo_cliente.flush()
                continue # Volta para o início do loop, esperando o próximo comando
            
            try:
                rede = ipaddress.IPv4Network(comando_cliente, strict=False)
                arquivo_cliente.write(f"\nINFO: Scan iniciado para {rede}. Aguarde...\n")
                arquivo_cliente.flush()
                
                resultados_scan = executar_scan_completo_na_rede(rede)
                
                if resultados_scan:
                    arquivo_cliente.write(f"\n--- Relatorio de Scan para {rede} ---\n")
                    for ip, status in resultados_scan:
                        linha = f"{ip:<18} | {status}\n"
                        arquivo_cliente.write(linha)
                else:
                    arquivo_cliente.write("INFO: Nenhum host encontrado na faixa especificada.\n")

                arquivo_cliente.write("\nINFO: Scan concluído. Digite um novo CIDR ou 'sair'.\n")
                arquivo_cliente.flush()

            except ValueError as e:
                arquivo_cliente.write(f"ERRO: Endereco de rede invalido '{comando_cliente}'. {e}\n")
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
    print("--- Servidor de Scan de Ativos em Rede ---")
    if PURESNMP_DISPONIVEL:
        print("[INFO] Funcionalidade SNMP ativa (via PureSNMP).")
    else:
        print("[AVISO] Biblioteca 'puresnmp' não encontrada. Funcionalidade SNMP desativada.")
    
    iniciar_servidor_principal()
