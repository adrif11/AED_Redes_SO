# --------------------------------------------------------------------------------
# SEÇÃO 1: IMPORTAÇÕES DE "CAIXAS DE FERRAMENTAS" (MÓDULOS)
# --------------------------------------------------------------------------------
import socket
import threading
import ipaddress
import subprocess # Essencial para chamar comandos externos como 'snmpget' e 'ping'
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import platform
from scapy.all import ARP, Ether, srp
# PySNMP não é mais necessário com esta abordagem

# --------------------------------------------------------------------------------
# SEÇÃO 2: CONFIGURAÇÕES GLOBAIS DO NOSSO SERVIDOR
# --------------------------------------------------------------------------------
PORTA_SERVIDOR = 35640
MAX_THREADS_SCAN_PING = 50
TIMEOUT_PING_SEGUNDOS = 2.0 # Ping é rápido
USAR_ARP_SCAN = True

# Configurações para o comando snmpget
SNMP_VERSION_CMD = '1'       # Para snmpget: -v1 ou -v2c. Usaremos v1 por simplicidade e maior compatibilidade.
SNMP_COMMUNITY_CMD = 'public' # Community string padrão
SNMP_TIMEOUT_CMD_S = 1       # Timeout em segundos para o comando snmpget (1 segundo)
SNMP_RETRIES_CMD = 0         # Retentativas para o comando snmpget (0 = não tentar de novo)
# OID do sysName no formato que o comando snmpget entende bem.
# MIB::Objeto.Índice (sysName.0 significa a primeira e geralmente única instância do sysName)
OID_SYSNAME_CMD = 'SNMPv2-MIB::sysName.0'

# --------------------------------------------------------------------------------
# SEÇÃO 3: FUNÇÕES AUXILIARES E DE SCAN
# --------------------------------------------------------------------------------
# Flag global para controlar a mensagem de erro do snmpget e evitar repetição.
SNMPGET_COMANDO_AUSENTE_FLAG = False

def obter_sysname_via_snmp_subprocess(ip_alvo):
    """
    Tenta obter o sysName de um host via SNMP chamando o comando 'snmpget'
    do sistema operacional através do subprocess.
    Assume que 'snmpget' está instalado e no PATH (típico em Linux com net-snmp-utils).

    Retorna:
        str: O sysName do dispositivo, se encontrado e parseado com sucesso.
        None: Se não conseguir obter ou parsear o sysName, ou se snmpget estiver ausente.
    """
    global SNMPGET_COMANDO_AUSENTE_FLAG # Permite modificar a flag global

    if SNMPGET_COMANDO_AUSENTE_FLAG: # Se já sabemos que snmpget não está lá, não tentamos de novo.
        return None

    # Monta o comando snmpget com seus argumentos.
    # Exemplo: snmpget -v1 -c public -t 1 -r 0 192.168.1.1 SNMPv2-MIB::sysName.0
    comando_snmpget = [
        'snmpget',                  # O nome do programa
        '-v', SNMP_VERSION_CMD,     # Versão do SNMP (ex: '-v1' ou '-v2c')
        '-c', SNMP_COMMUNITY_CMD,   # Community string (ex: '-c public')
        '-t', str(SNMP_TIMEOUT_CMD_S), # Timeout em segundos (ex: '-t 1')
        '-r', str(SNMP_RETRIES_CMD),   # Número de retentativas (ex: '-r 0')
        str(ip_alvo),               # O IP do dispositivo alvo
        OID_SYSNAME_CMD             # O OID que queremos buscar (sysName.0)
    ]

    try:
        # Executa o comando snmpget.
        # 'capture_output=True' guarda o que o comando imprimir na tela.
        # 'text=True' faz com que a saída seja tratada como texto (string).
        # 'timeout' define um tempo máximo para o comando rodar.
        # 'check=False' evita que o programa Python pare com erro se o snmpget falhar.
        resultado_processo = subprocess.run(
            comando_snmpget,
            capture_output=True,
            text=True, # Decodifica a saída para string automaticamente
            timeout=SNMP_TIMEOUT_CMD_S + 2, # Um timeout um pouco maior para o subprocesso em si
            check=False # Importante para não levantar exceção em retornos não-zero
        )

        # Verifica se o comando snmpget foi executado com sucesso (código de retorno 0).
        if resultado_processo.returncode == 0:
            saida_snmpget = resultado_processo.stdout.strip() # Pega a saída e tira espaços extras.
            # A saída do snmpget para sysName.0 geralmente é algo como:
            # SNMPv2-MIB::sysName.0 = STRING: "NomeDoDispositivoLegal"
            # ou às vezes sem o tipo STRING explícito, dependendo do agente SNMP:
            # SNMPv2-MIB::sysName.0 = "NomeDoDispositivoLegal"
            # Precisamos extrair apenas o "NomeDoDispositivoLegal".

            # Esta expressão regular tenta capturar o valor após "STRING: " ou diretamente após o " = ".
            # Ela procura por:
            #   um sinal de igualdade, opcionalmente com espaços ao redor (\s*=\s*)
            #   opcionalmente, a palavra "STRING:" seguida de espaços ((?:STRING:\s*)?)
            #   opcionalmente, uma aspa dupla (\")?
            #   O conteúdo que queremos capturar ([^"]+) - um ou mais caracteres que NÃO são aspas duplas.
            #      Se não houver aspas, ele pega até o fim da linha ou o próximo espaço,
            #      então vamos refinar para pegar após o último ':' ou '=' se não houver aspas.
            #   opcionalmente, uma aspa dupla no final (\")$
            #
            # Uma forma mais simples e robusta para a saída comum:
            # Tentar encontrar o que vem depois do último ": " ou " = "
            partes = None
            if '"' in saida_snmpget: # Se tem aspas, é mais fácil
                 match = re.search(r':\s*"(.*)"$', saida_snmpget) # Captura entre aspas após o último :
                 if match:
                     return match.group(1).strip()
            else: # Se não tem aspas, pode ser mais simples
                if "=" in saida_snmpget:
                    partes = saida_snmpget.split("=", 1)
                elif ":" in saida_snmpget: # Menos comum para o valor direto, mas como fallback
                    partes = saida_snmpget.split(":", 1)

                if partes and len(partes) > 1:
                    valor_bruto = partes[1].strip()
                    # Remove "STRING: " se presente no início do valor bruto
                    if valor_bruto.upper().startswith("STRING:"):
                        valor_bruto = valor_bruto[len("STRING:"):].strip()
                    # Remove aspas se ainda estiverem presentes (caso raro sem o match anterior)
                    if valor_bruto.startswith('"') and valor_bruto.endswith('"'):
                        valor_bruto = valor_bruto[1:-1]
                    return valor_bruto if valor_bruto else None

            # print(f"  [SNMP Subprocess Parse Falha DEBUG] Não foi possível parsear sysName da saída para {ip_alvo}: '{saida_snmpget}'")
            return None # Não conseguiu parsear
        else:
            # Comando snmpget falhou (ex: timeout, host não responde SNMP, community errada)
            # A mensagem de erro do snmpget estaria em resultado_processo.stderr
            # print(f"  [SNMP Subprocess Comando Falhou DEBUG] snmpget para {ip_alvo} falhou (ret: {resultado_processo.returncode}). Stderr: {resultado_processo.stderr.strip()}")
            return None

    except subprocess.TimeoutExpired:
        # print(f"  [SNMP Subprocess Timeout DEBUG] Timeout ao executar snmpget para {ip_alvo}")
        return None
    except FileNotFoundError:
        # Este erro acontece se o comando 'snmpget' NÃO FOI ENCONTRADO no sistema.
        if not SNMPGET_COMANDO_AUSENTE_FLAG: # Mostra a mensagem só uma vez.
            print(f"[SNMP ERRO CRÍTICO] Comando 'snmpget' não encontrado no sistema.")
            print("Para funcionalidade SNMP, instale o 'net-snmp-utils' (Linux) ou equivalente e garanta que esteja no PATH.")
            SNMPGET_COMANDO_AUSENTE_FLAG = True # Marca que o comando está ausente para não repetir o erro.
        return None # Retorna None, indicando que o SNMP não pôde ser executado.
    except Exception as e:
        # print(f"  [SNMP Subprocess Exceção DEBUG] Exceção ao executar snmpget para {ip_alvo}: {e}")
        return None

# --- Funções de Ping, ARP, Scan Combinado (sem alterações) ---
def testar_host_com_ping(ip_host_para_testar):
    ip_texto = str(ip_host_para_testar)
    if platform.system() == "Windows":
        comando = ['ping', '-n', '1', '-w', str(int(TIMEOUT_PING_SEGUNDOS * 1000)), ip_texto]
    else: # Assume Linux ou similar
        comando = ['ping', '-c', '1', '-W', str(TIMEOUT_PING_SEGUNDOS), '-i', '0.2', ip_texto]

    print(f"  [Ping DEBUG] Executando: {' '.join(comando)}") # DESCOMENTADO

    try:
        startupinfo = None
        if platform.system() == "Windows":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        resultado_comando = subprocess.run(
            comando, 
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, 
            timeout=TIMEOUT_PING_SEGUNDOS + 1.0,
            startupinfo=startupinfo,
            text=True
        )

        if resultado_comando.returncode == 0:
            print(f"  [Ping DEBUG] Sucesso para {ip_texto}") # DESCOMENTADO
            return True
        else:
            print(f"  [Ping DEBUG] Falha para {ip_texto}. Código: {resultado_comando.returncode}. Erro: {resultado_comando.stderr.strip()}") # DESCOMENTADO
            return False

    except subprocess.TimeoutExpired:
        print(f"  [Ping DEBUG] Timeout EXPIROU para {ip_texto} ao executar o comando.") # DESCOMENTADO
        return False
    except FileNotFoundError:
        print(f"  [Ping ERRO CRÍTICO] Comando 'ping' não encontrado para {ip_texto}. Verifique o PATH do sistema.") # DESCOMENTADO
        return False
    except Exception as e_ping:
        print(f"  [Ping ERRO CRÍTICO] Exceção inesperada para {ip_texto}: {e_ping}") # DESCOMENTADO
        return False

def scan_arp_rede_local(objeto_rede_alvo):
    ips_ativos_via_arp = []
    try:
        pacote_arp_requisicao = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(objeto_rede_alvo))
        lista_pacotes_respondidos, _ = srp(pacote_arp_requisicao, timeout=1, verbose=False)
        if lista_pacotes_respondidos:
            for _,p_resp in lista_pacotes_respondidos: ips_ativos_via_arp.append(p_resp.psrc)
    except Exception as e: print(f"  [ARP ERRO] {e}")
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
        for ip_arp_add in ips_arp:
            ativos.add(ip_arp_add)
        print(f"[SCAN INFO] Fase 1 (ARP) concluída. {len(ips_arp)} hosts encontrados via ARP (adicionados ao conjunto: {len(ativos)}).")

    print(f"[SCAN INFO] Fase 2: Scan Ping para {objeto_rede_alvo}...")
    ips_ping = scan_ping_em_paralelo(objeto_rede_alvo)
    for ip_ping_add in ips_ping:
        ativos.add(ip_ping_add)
    print(f"[SCAN INFO] Fase 2 (Ping) concluída. {len(ips_ping)} hosts encontrados ou confirmados via Ping (total no conjunto: {len(ativos)}).")

    total = len(ativos)
    if total > 0: print(f"[SCAN INFO] Scan total finalizado! {total} hosts ativos únicos. :)")
    else: print(f"[SCAN INFO] Scan total finalizado. Nenhum host ativo. :(")
    return list(ativos)

# --- Função de Gerenciar Cliente (agora chama obter_sysname_via_snmp_subprocess) ---
def gerenciar_conexao_cliente(sock_cli, end_cli):
    global SNMPGET_COMANDO_AUSENTE_FLAG
    print(f"[CONEXÃO] Cliente {end_cli} conectou-se!")
    try:
        while True:
            dados_brutos = sock_cli.recv(1024)
            if not dados_brutos:
                print(f"[CONEXÃO] Cliente {end_cli} desconectou (sem dados).")
                break
            try:
                dados = dados_brutos.decode('utf-8').strip()
            except UnicodeDecodeError:
                print(f"[ERRO] Cliente {end_cli} enviou dados não decodificáveis como UTF-8. Ignorando.")
                sock_cli.sendall(b"ERRO: Os dados enviados nao sao UTF-8 validos.\n")
                continue

            print(f"[CLIENTE {end_cli}] Requisição: '{dados}'")

            if dados.startswith("GET /") or dados.startswith("POST /"):
                print(f"[INFO] Cliente {end_cli} parece ser um navegador. Enviando resposta HTTP simples.")
                http_response = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nServidor de Scan de Rede. Use o programa cliente para interagir.\n"
                sock_cli.sendall(http_response.encode('utf-8'))
                break

            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$', dados):
                mensagem_erro_formato = "ERRO: Formato CIDR inválido. Use IP/prefixo (ex: 192.168.1.0/24).\n"
                sock_cli.sendall(mensagem_erro_formato.encode('utf-8')) # CORRIGIDO
                continue
            try:
                rede = ipaddress.IPv4Network(dados, strict=False)
                sock_cli.sendall(f"INFO: Scan iniciado para {rede}. Aguarde...\n".encode('utf-8'))
                
                ips_ativos = executar_scan_completo_na_rede(rede)
                
                if ips_ativos:
                    sock_cli.sendall(f"RESULTADO: {len(ips_ativos)} host(s) ativo(s):\n".encode('utf-8'))
                    for ip in ips_ativos:
                        sysname = obter_sysname_via_snmp_subprocess(ip)
                        linha = f"{ip} {sysname}\n" if sysname else f"{ip}\n"
                        sock_cli.sendall(linha.encode('utf-8'))
                else:
                    sock_cli.sendall(b"RESULTADO: Nenhum host ativo encontrado.\n")
                
                sock_cli.sendall("INFO: Scan para esta rede concluído.\n".encode('utf-8')) # CORRIGIDO
            except ValueError as e:
                mensagem_erro_val = f"ERRO: Endereço de rede inválido '{dados}'. {e}\n"
                sock_cli.sendall(mensagem_erro_val.encode('utf-8')) # CORRIGIDO
    except ConnectionResetError:
        print(f"[CONEXÃO] Cliente {end_cli} resetou a conexão.")
    except Exception as e:
        print(f"[ERRO] Cliente {end_cli}: {e}")
    finally:
        print(f"[CONEXÃO] Encerrando com {end_cli}.")
        sock_cli.close()

# --- Função de Iniciar Servidor (sem alterações na lógica principal) ---
def iniciar_servidor_principal():
    sock_serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock_serv.bind(('0.0.0.0', PORTA_SERVIDOR))
        print(f"[SERVIDOR] Online na porta {PORTA_SERVIDOR}.")
    except OSError as e:
        print(f"[SERVIDOR ERRO] Bind falhou na porta {PORTA_SERVIDOR}: {e}")
        return
    sock_serv.listen(5)
    print(f"[SERVIDOR] Aguardando conexões...")
    try:
        while True:
            cli_sock, cli_end = sock_serv.accept()
            threading.Thread(target=gerenciar_conexao_cliente, args=(cli_sock, cli_end), daemon=True).start()
    except KeyboardInterrupt: print("\n[SERVIDOR] Desligando...")
    except Exception as e: print(f"[SERVIDOR ERRO FATAL] {e}")
    finally: sock_serv.close()

# --------------------------------------------------------------------------------
# SEÇÃO 6: PONTO DE ENTRADA DO SCRIPT
# --------------------------------------------------------------------------------
if __name__ == "__main__":
    if platform.system() != "Linux" and USAR_ARP_SCAN:
        print("[AVISO] Scan ARP com Scapy pode precisar de root/admin fora do Linux.")
    print("[INFO] Iniciando servidor. A funcionalidade SNMP usará o comando 'snmpget' do sistema.")
    iniciar_servidor_principal()