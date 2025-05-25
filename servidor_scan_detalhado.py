# --------------------------------------------------------------------------------
# SEÇÃO 1: IMPORTAÇÕES DE "CAIXAS DE FERRAMENTAS" (MÓDULOS)
# --------------------------------------------------------------------------------
# No Python, quando queremos usar funcionalidades que não vêm embutidas na linguagem
# base, nós "importamos" módulos. Pense neles como caixas de ferramentas especializadas.

import socket # Caixa de ferramentas para comunicação em rede (criar conexões, enviar/receber dados).
import threading # Permite que nosso programa faça várias coisas ao mesmo tempo (ex: atender vários clientes).
import ipaddress # Ajuda a entender e manipular endereços IP e redes (ex: 192.168.1.0/24).
import subprocess # Permite que nosso programa Python execute outros programas/comandos do sistema operacional (como o 'ping').
import re # "Regular Expressions" - uma mini-linguagem para encontrar padrões em textos. Útil para validar formatos.
from concurrent.futures import ThreadPoolExecutor, as_completed # Ferramentas para executar tarefas em paralelo, tornando o scan mais rápido.
import platform # Para descobrir informações sobre o sistema operacional onde o script está rodando (ex: Linux, Windows).
from scapy.all import ARP, Ether, srp # Scapy é uma poderosa caixa de ferramentas para criar e manipular pacotes de rede. Usamos para o ARP scan.

# Usando o CommandGenerator (cmdgen) do PySNMP, que funcionou no seu ambiente.
try:
    from pysnmp.entity.rfc3413.oneliner import cmdgen
    CMDGEN_DISPONIVEL = True
    print("[INFO PySNMP] Módulo 'cmdgen' importado com sucesso.")
except ModuleNotFoundError:
    print("[ERRO FATAL PySNMP] Não foi possível importar 'cmdgen' de 'pysnmp.entity.rfc3413.oneliner'.")
    print("Este módulo é necessário para a funcionalidade SNMP. Verifique a instalação do PySNMP.")
    print("A funcionalidade SNMP não estará disponível.")
    CMDGEN_DISPONIVEL = False
except ImportError as e_cmdgen_import:
    print(f"[ERRO FATAL PySNMP] Erro ao importar 'cmdgen': {e_cmdgen_import}")
    print("A funcionalidade SNMP não estará disponível.")
    CMDGEN_DISPONIVEL = False

# --------------------------------------------------------------------------------
# SEÇÃO 2: CONFIGURAÇÕES GLOBAIS DO NOSSO SERVIDOR
# --------------------------------------------------------------------------------
# Aqui definimos algumas "constantes" - valores que não vão mudar enquanto o programa roda.
# Escrever em MAIÚSCULAS é uma convenção em Python para indicar que são constantes.

PORTA_SERVIDOR = 35640      # Número da "porta" de comunicação que nosso servidor vai usar.
MAX_THREADS_SCAN_PING = 50  # Quantos "trabalhadores" (threads) no máximo vão fazer pings ao mesmo tempo.
TIMEOUT_PING_SEGUNDOS = 0.5 # Tempo máximo (em segundos) que vamos esperar por uma resposta de um ping.
USAR_ARP_SCAN = True        # Se True, vamos tentar o ARP scan (rápido em redes locais). Se False, só ping.

# Configurações específicas para o SNMP
SNMP_COMMUNITY_STRING = 'public' # "Senha" comum para acesso SNMP (somente leitura).
SNMP_PORTA = 161                 # Porta padrão para requisições SNMP.
SNMP_TIMEOUT_SEGUNDOS = 1.0      # Tempo máximo de espera por uma resposta SNMP (aumentado para 1s).
SNMP_RETENTATIVAS = 0            # Quantas vezes tentar de novo se uma requisição SNMP falhar.

# --------------------------------------------------------------------------------
# SEÇÃO 3: FUNÇÕES AUXILIARES E DE SCAN
# --------------------------------------------------------------------------------
# Funções são blocos de código que realizam uma tarefa específica.
# Elas ajudam a organizar o código e evitam repetição.
# 'def' é a palavra-chave em Python para definir uma função.

def obter_sysname_via_snmp(ip_alvo):
    """
    Esta função tenta buscar o "sysName" (nome do sistema) de um dispositivo
    na rede usando o protocolo SNMP com CommandGenerator do pysnmp.

    Argumentos:
        ip_alvo (str): O endereço IP do dispositivo que queremos consultar.

    Retorna:
        str: O sysName do dispositivo, se encontrado.
        None: Se não conseguir encontrar o sysName ou se ocorrer um erro.
    """
    # Verifica primeiro se a ferramenta cmdgen do PySNMP está disponível.
    # Se não foi importada com sucesso lá no começo, não adianta nem tentar.
    if not CMDGEN_DISPONIVEL:
        # print(f"  [SNMP DEBUG] cmdgen não está disponível. Pulando SNMP para {ip_alvo}.")
        return None # Retorna "nada" (None) indicando que o SNMP não pode ser usado.

    # print(f"  [SNMP cmdgen Tentativa DEBUG] Verificando sysName para {ip_alvo}...") # Linha para depuração

    # 1. Cria uma instância (um "objeto") do CommandGenerator.
    #    Pense nisso como pegar a "máquina de fazer pedidos SNMP" da caixa de ferramentas cmdgen.
    gerador_comandos_snmp = cmdgen.CommandGenerator()

    # 2. Executa o comando GET do SNMP para buscar o sysName.
    #    A função 'getCmd' desta máquina 'gerador_comandos_snmp' precisa de alguns "ingredientes":
    #    a) Informações da comunidade SNMP:
    #       - 'cmdgen.CommunityData(SNMP_COMMUNITY_STRING, mpModel=0)'
    #         Cria um objeto que guarda a "palavra-chave" (community string, ex: 'public')
    #         e a versão do SNMP a ser usada (mpModel=0 significa SNMPv1, a mais simples).
    #    b) Informações do Alvo (para onde enviar o pedido):
    #       - 'cmdgen.UdpTransportTarget((str(ip_alvo), SNMP_PORTA), timeout=SNMP_TIMEOUT_SEGUNDOS, retries=SNMP_RETENTATIVAS)'
    #         Define o IP do dispositivo alvo (convertido para texto com str()), a porta SNMP (161),
    #         quanto tempo esperar pela resposta (timeout) e quantas vezes tentar de novo (retries).
    #    c) O OID (Object Identifier) da informação que queremos:
    #       - '1.3.6.1.2.1.1.5.0' é o "endereço universal" dentro do "catálogo" SNMP
    #         que corresponde ao 'sysName' (nome do sistema) do dispositivo.
    #
    #    A função 'getCmd' retorna 4 coisas diretamente (não um iterador como no hlapi):
    #    - indicacao_erro: Informa se houve algum problema na "viagem" do pedido SNMP (ex: tempo esgotou, IP não alcançável).
    #    - status_erro: Se o dispositivo respondeu, mas com uma mensagem de erro SNMP (ex: "essa informação não existe aqui").
    #    - indice_erro: Se 'status_erro' aconteceu, ajuda a identificar qual item do pedido falhou (mais útil se pedíssemos várias coisas).
    #    - variaveis_recebidas: Se tudo deu certo, aqui vem a informação que pedimos (uma lista de pares: OID e o Valor).
    indicacao_erro, status_erro, indice_erro, variaveis_recebidas = gerador_comandos_snmp.getCmd(
        cmdgen.CommunityData(SNMP_COMMUNITY_STRING, mpModel=0),
        cmdgen.UdpTransportTarget(
            (str(ip_alvo), SNMP_PORTA),
            timeout=SNMP_TIMEOUT_SEGUNDOS,
            retries=SNMP_RETENTATIVAS
        ),
        '1.3.6.1.2.1.1.5.0' # OID para sysName
    )

    # 3. Verifica se houve algum erro.
    if indicacao_erro:
        # Se 'indicacao_erro' contiver alguma mensagem, significa que um problema de comunicação ocorreu.
        # print(f"  [SNMP cmdgen Falha DEBUG] Indicação de erro para {ip_alvo}: {indicacao_erro}")
        return None # Retorna "nada" para indicar falha.
    elif status_erro:
        # Se o dispositivo respondeu, mas indicando um erro SNMP.
        # O '.prettyPrint()' ajuda a mostrar o erro de forma mais legível.
        # A parte com 'indice_erro' e 'variaveis_recebidas' tenta dar mais detalhes sobre qual OID falhou.
        # print(f"  [SNMP cmdgen Falha DEBUG] Status de erro para {ip_alvo}: {status_erro.prettyPrint()} em {indice_erro and variaveis_recebidas[int(indice_erro) - 1][0] or '?'}")
        return None # Retorna "nada".
    else:
        # Se não houve 'indicacao_erro' nem 'status_erro', o pedido SNMP provavelmente foi bem-sucedido!
        # Agora, verificamos se recebemos de volta as variáveis (o sysName).
        # 'variaveis_recebidas' é uma lista. 'len(variaveis_recebidas)' nos diz quantos itens tem na lista.
        if variaveis_recebidas and len(variaveis_recebidas) > 0:
            # Se a lista não está vazia e tem pelo menos um item:
            # O sysName que queremos é o "Valor" do primeiro par (OID, Valor) na lista.
            # 'variaveis_recebidas[0]' pega o primeiro par (que é uma tupla).
            # 'variaveis_recebidas[0][1]' pega o segundo item desse par, que é o Valor do sysName.
            objeto_sysname = variaveis_recebidas[0][1]
            # O valor pode vir num formato especial do SNMP (OctetString).
            # O método '.prettyPrint()' converte esse valor para um texto (string) normal.
            return objeto_sysname.prettyPrint() # Sucesso! Retorna o nome do sistema.
        else:
            # Se não veio erro, mas também não veio nenhuma variável. Estranho, mas pode acontecer.
            # print(f"  [SNMP cmdgen Falha DEBUG] Nenhuma variável (sysName) retornada para {ip_alvo}, embora não tenha havido erro.")
            return None # Retorna "nada".

def testar_host_com_ping(ip_host_para_testar):
    """
    Verifica se um host (dispositivo) na rede está ativo (responde a "ping").
    Usa o comando 'ping' do sistema operacional.

    Argumentos:
        ip_host_para_testar (ipaddress.IPv4Address ou str): O IP do host a ser testado.

    Retorna:
        bool: True se o host responder ao ping, False caso contrário.
    """
    ip_texto = str(ip_host_para_testar) # Garante que o IP seja uma string.
    # Monta o comando 'ping' para Linux.
    comando = ['ping', '-c', '1', '-W', str(TIMEOUT_PING_SEGUNDOS), '-i', '0.2', ip_texto]
    try:
        # Executa o comando 'ping' e não mostra sua saída na tela.
        resultado_comando = subprocess.run(
            comando,
            stdout=subprocess.DEVNULL, # Esconde a saída padrão do comando.
            stderr=subprocess.DEVNULL, # Esconde as mensagens de erro do comando.
            timeout=TIMEOUT_PING_SEGUNDOS + 0.5 # Timeout para o subprocesso, um pouco maior que o do ping.
        )
        # Se o comando 'ping' retornou código 0, significa sucesso.
        return resultado_comando.returncode == 0
    except subprocess.TimeoutExpired: # Se o subprocesso demorou demais.
        return False
    except Exception: # Para qualquer outro erro ao tentar rodar o ping.
        return False

def scan_arp_rede_local(objeto_rede_alvo):
    """
    Realiza um scan usando o protocolo ARP para descobrir hosts na rede local.
    Usa a biblioteca Scapy.

    Argumentos:
        objeto_rede_alvo (ipaddress.IPv4Network): O objeto representando a rede a ser escaneada.

    Retorna:
        list: Uma lista de strings, cada uma sendo um IP ativo encontrado via ARP.
    """
    ips_ativos_via_arp = [] # Lista para guardar os IPs que responderem.
    try:
        # Monta o pacote ARP: Ethernet de broadcast / ARP Request para a rede alvo.
        pacote_arp_requisicao = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(objeto_rede_alvo))
        # Envia os pacotes e recebe as respostas (srp = Send and Receive packets at layer 2).
        # timeout=1 segundo, verbose=False para não imprimir mensagens do Scapy.
        lista_pacotes_respondidos, _ = srp(pacote_arp_requisicao, timeout=1, verbose=False)

        if lista_pacotes_respondidos: # Se houve respostas...
            # Para cada par (pacote enviado, pacote recebido) na lista de respondidos...
            for _, pacote_resposta_arp in lista_pacotes_respondidos:
                # Adiciona o IP de origem da resposta ARP ('psrc') à nossa lista.
                ips_ativos_via_arp.append(pacote_resposta_arp.psrc)
    except Exception as e_arp: # Se ocorrer algum erro com o Scapy.
        print(f"  [ARP ERRO] Falha durante o scan ARP: {e_arp}")
    return list(set(ips_ativos_via_arp)) # Retorna a lista sem IPs duplicados.

def scan_ping_em_paralelo(objeto_rede_alvo):
    """
    Realiza um scan de ping em múltiplos IPs da rede de forma paralela (ao mesmo tempo).
    Usa 'ThreadPoolExecutor' para gerenciar as tarefas de ping.

    Argumentos:
        objeto_rede_alvo (ipaddress.IPv4Network): O objeto da rede a ser escaneada.

    Retorna:
        list: Uma lista de strings, cada uma sendo um IP ativo encontrado via Ping.
    """
    ips_ativos_via_ping = [] # Lista para os IPs que responderem.
    # Pega todos os IPs "utilizáveis" da rede (ex: .1 a .254 para um /24).
    lista_ips_para_testar = list(objeto_rede_alvo.hosts())

    if not lista_ips_para_testar: # Se não há IPs para testar...
        return [] # Retorna lista vazia.

    # 'with' garante que o ThreadPoolExecutor seja fechado corretamente no final.
    # 'max_workers' é o número de "pingadores" simultâneos.
    with ThreadPoolExecutor(max_workers=MAX_THREADS_SCAN_PING) as executor:
        # Cria um "mapa" onde cada "tarefa futura de ping" está ligada ao IP que ela vai testar.
        # 'executor.submit(função, argumento)' agenda a função para ser executada.
        mapa_futuro_para_ip = {
            executor.submit(testar_host_com_ping, ip_atual): ip_atual
            for ip_atual in lista_ips_para_testar
        }
        # 'as_completed' nos entrega cada tarefa assim que ela termina.
        for futuro_da_tarefa_ping in as_completed(mapa_futuro_para_ip):
            ip_associado_ao_futuro = mapa_futuro_para_ip[futuro_da_tarefa_ping] # Descobre qual IP era.
            try:
                # '.result()' pega o resultado da função testar_host_com_ping (True ou False).
                if futuro_da_tarefa_ping.result():
                    ips_ativos_via_ping.append(str(ip_associado_ao_futuro)) # Adiciona IP à lista se True.
            except Exception: # Se der erro ao pegar o resultado da tarefa.
                pass # Ignora e continua.
    return list(set(ips_ativos_via_ping)) # Retorna lista sem duplicatas.

def executar_scan_completo_na_rede(objeto_rede_alvo):
    """
    Orquestra o scan da rede, combinando ARP (se habilitado) e Ping.

    Argumentos:
        objeto_rede_alvo (ipaddress.IPv4Network): A rede a ser escaneada.

    Retorna:
        list: Uma lista de IPs (strings) ativos encontrados na rede.
    """
    ativos = set() # Usamos um 'set' para automaticamente evitar IPs duplicados.

    if USAR_ARP_SCAN: # Se a configuração global diz para usar ARP...
        print(f"[SCAN INFO] Fase 1: Scan ARP para {objeto_rede_alvo}...")
        ips_arp = scan_arp_rede_local(objeto_rede_alvo) # Faz o scan ARP.
        for ip_arp_add in ips_arp: # Para cada IP encontrado pelo ARP...
            ativos.add(ip_arp_add) # Adiciona ao nosso conjunto de IPs ativos.
        print(f"[SCAN INFO] Fase 1 (ARP) concluída. {len(ips_arp)} hosts encontrados via ARP (adicionados ao conjunto: {len(ativos)}).")

    print(f"[SCAN INFO] Fase 2: Scan Ping para {objeto_rede_alvo}...")
    ips_ping = scan_ping_em_paralelo(objeto_rede_alvo) # Faz o scan Ping.
    for ip_ping_add in ips_ping: # Para cada IP encontrado pelo Ping...
        ativos.add(ip_ping_add) # Adiciona ao conjunto (se já não estiver lá do ARP).
    print(f"[SCAN INFO] Fase 2 (Ping) concluída. {len(ips_ping)} hosts encontrados ou confirmados via Ping (total no conjunto: {len(ativos)}).")

    total = len(ativos) # Quantos IPs únicos foram encontrados no total.
    if total > 0:
        print(f"[SCAN INFO] Scan total finalizado! {total} hosts ativos únicos. :)")
    else:
        print(f"[SCAN INFO] Scan total finalizado. Nenhum host ativo. :(")
    return list(ativos) # Retorna como uma lista.

# --------------------------------------------------------------------------------
# SEÇÃO 4: FUNÇÃO PARA GERENCIAR CADA CLIENTE CONECTADO
# --------------------------------------------------------------------------------
def gerenciar_conexao_cliente(sock_cli, end_cli): # sock_cli: telefone do cliente, end_cli: endereço do cliente
    """
    Esta função é executada para cada cliente que se conecta ao servidor.
    Ela recebe a requisição do cliente (CIDR), processa e envia a resposta.
    """
    print(f"[CONEXÃO] Cliente {end_cli} conectou-se!") # Avisa no console do servidor.
    try: # Bloco principal para tratar toda a comunicação com este cliente.
        while True: # Loop para permitir que o cliente faça vários pedidos.
            # Espera receber dados (o CIDR) do cliente.
            # recv(1024) lê até 1024 bytes. decode transforma bytes em texto. strip tira espaços.
            dados = sock_cli.recv(1024).decode('utf-8').strip()

            if not dados: # Se o cliente não enviou nada (ex: fechou a conexão)...
                print(f"[CONEXÃO] Cliente {end_cli} desconectou ou enviou dados vazios."); break # Sai do loop.

            print(f"[CLIENTE {end_cli}] Requisição: '{dados}'") # Mostra o que o cliente pediu.

            # Valida o formato do CIDR (ex: 192.168.1.0/24) usando Expressão Regular.
            # re.match verifica se o INÍCIO do texto 'dados' bate com o padrão.
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$', dados):
                # Se não bateu com o padrão...
                sock_cli.sendall("ERRO: Formato CIDR inválido. Use IP/prefixo (ex: 192.168.1.0/24).\n")
                continue # Pula o resto e volta para o início do while, esperando nova entrada.

            try: # Tenta processar o CIDR e fazer o scan.
                # Converte a string CIDR para um objeto de rede Python.
                # strict=False permite CIDRs que apontam para o endereço da rede (ex: x.x.x.0/24).
                rede = ipaddress.IPv4Network(dados, strict=False)

                # Avisa o cliente que o scan começou.
                sock_cli.sendall(f"INFO: Scan iniciado para {rede}. Aguarde...\n".encode('utf-8'))

                # Chama a função principal de scan.
                ips_ativos = executar_scan_completo_na_rede(rede)

                if ips_ativos: # Se encontrou algum IP ativo...
                    # Envia a quantidade para o cliente.
                    sock_cli.sendall(f"RESULTADO: {len(ips_ativos)} host(s) ativo(s):\n".encode('utf-8'))
                    # Para cada IP ativo na lista...
                    for ip in ips_ativos:
                        sysname = obter_sysname_via_snmp(ip) # Tenta pegar o nome do sistema via SNMP.
                        # Monta a linha de resposta: "IP NomeDoSistema" ou só "IP".
                        linha = f"{ip} {sysname}\n" if sysname else f"{ip}\n"
                        sock_cli.sendall(linha.encode('utf-8')) # Envia a linha.
                else: # Se não encontrou nenhum IP ativo...
                    sock_cli.sendall(b"RESULTADO: Nenhum host ativo encontrado.\n")
                # Avisa que o scan para ESTA rede terminou.
                sock_cli.sendall("INFO: Scan para esta rede concluído.\n")
            except ValueError as e: # Se o ipaddress.IPv4Network deu erro (CIDR com valor inválido).
                sock_cli.sendall(f"ERRO: Endereço de rede inválido '{dados}'. {e}\n".encode('utf-8'))
    except ConnectionResetError: # Se o cliente fechar a conexão de forma abrupta.
        print(f"[CONEXÃO] Cliente {end_cli} resetou a conexão.")
    except Exception as e: # Para qualquer outro erro durante a conversa com este cliente.
        print(f"[ERRO] Cliente {end_cli}: {e}")
    finally: # Aconteça o que acontecer (erro ou não)...
        print(f"[CONEXÃO] Encerrando com {end_cli}.")
        sock_cli.close() # Fecha o "telefone particular" com este cliente.

# --------------------------------------------------------------------------------
# SEÇÃO 5: FUNÇÃO PRINCIPAL PARA INICIAR O SERVIDOR
# --------------------------------------------------------------------------------
def iniciar_servidor_principal():
    """Configura e inicia o servidor TCP principal."""
    # Cria o "telefone principal" do servidor (socket de escuta).
    sock_serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # IPv4, TCP
    # Permite que o servidor use a mesma porta rapidamente após ser reiniciado.
    sock_serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        # "Conecta o telefone na tomada": liga o socket a um endereço (todas as interfaces) e porta.
        sock_serv.bind(('0.0.0.0', PORTA_SERVIDOR))
        print(f"[SERVIDOR] Online na porta {PORTA_SERVIDOR}.")
    except OSError as e: # Se não conseguir usar a porta (ex: já em uso).
        print(f"[SERVIDOR ERRO] Bind falhou na porta {PORTA_SERVIDOR}: {e}")
        return # Não pode continuar.

    sock_serv.listen(5) # Coloca o servidor para "escutar" por até 5 conexões na fila.
    print(f"[SERVIDOR] Aguardando conexões...")
    try:
        while True: # Loop infinito para sempre aceitar novos clientes.
            # ".accept()" espera uma ligação. Quando chega, retorna um NOVO socket
            # para ESTE cliente ('cli_sock') e o endereço do cliente ('cli_end').
            cli_sock, cli_end = sock_serv.accept()
            # Cria um "assistente" (thread) para cuidar deste novo cliente.
            # 'target' é a função que o assistente vai rodar.
            # 'args' são os ingredientes para essa função.
            # 'daemon=True' faz o assistente fechar se o servidor principal fechar.
            assistente = threading.Thread(target=gerenciar_conexao_cliente, args=(cli_sock, cli_end), daemon=True)
            assistente.start() # O assistente começa a trabalhar.
    except KeyboardInterrupt: # Se você apertar Ctrl+C para parar o servidor.
        print("\n[SERVIDOR] Desligando...")
    except Exception as e: # Qualquer outro erro grave no servidor.
        print(f"[SERVIDOR ERRO FATAL] {e}")
    finally: # Não importa como saiu do loop...
        sock_serv.close() # Fecha o "telefone principal" do servidor.

# --------------------------------------------------------------------------------
# SEÇÃO 6: PONTO DE ENTRADA DO SCRIPT (QUANDO EXECUTADO DIRETAMENTE)
# --------------------------------------------------------------------------------
# Esta parte só roda se você executar este arquivo diretamente (ex: python nome_do_arquivo.py)
if __name__ == "__main__":
    # Aviso sobre o Scapy e permissões se não estiver no Linux.
    if platform.system() != "Linux" and USAR_ARP_SCAN:
        print("[AVISO] Scan ARP com Scapy pode precisar de root/admin fora do Linux.")

    # Verifica se o cmdgen (ferramenta SNMP) foi importado com sucesso.
    if CMDGEN_DISPONIVEL:
        print("[INFO PySNMP] Iniciando servidor com funcionalidade SNMP (via cmdgen).")
    else:
        # Se CMDGEN_DISPONIVEL for False, significa que a importação do cmdgen falhou lá no começo.
        print("[AVISO PySNMP] Iniciando servidor SEM funcionalidade SNMP devido a erro na importação do PySNMP (cmdgen).")
    
    iniciar_servidor_principal() # Chama a função para ligar o servidor!