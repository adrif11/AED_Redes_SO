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
from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity # Kit de ferramentas para SNMP!

# --------------------------------------------------------------------------------
# SEÇÃO 2: CONFIGURAÇÕES GLOBAIS DO NOSSO SERVIDOR
# --------------------------------------------------------------------------------
# Aqui definimos algumas "constantes" - valores que não vão mudar enquanto o programa roda.
# Escrever em MAIÚSCULAS é uma convenção em Python para indicar que são constantes.

PORTA_SERVIDOR = 35640      # Número da "porta" de comunicação que nosso servidor vai usar. Pense numa sala numerada num prédio.
MAX_THREADS_SCAN_PING = 50  # Quantos "trabalhadores" (threads) no máximo vão fazer pings ao mesmo tempo.
TIMEOUT_PING_SEGUNDOS = 0.5 # Tempo máximo (em segundos) que vamos esperar por uma resposta de um ping.
USAR_ARP_SCAN = True        # Se True, vamos tentar o ARP scan (rápido em redes locais). Se False, só ping.

# Configurações específicas para o SNMP
SNMP_COMMUNITY_STRING = 'public' # "Senha" comum para acessar dados SNMP (somente leitura). Muitos dispositivos vêm com 'public' por padrão.
SNMP_PORTA = 161                 # Porta padrão para requisições SNMP.
SNMP_TIMEOUT_SEGUNDOS = 0.5      # Tempo máximo de espera por uma resposta SNMP.
SNMP_RETENTATIVAS = 0            # Quantas vezes tentar de novo se uma requisição SNMP falhar (0 = não tentar de novo).

# --------------------------------------------------------------------------------
# SEÇÃO 3: FUNÇÕES AUXILIARES E DE SCAN
# --------------------------------------------------------------------------------
# Funções são blocos de código que realizam uma tarefa específica.
# Elas ajudam a organizar o código e evitam repetição.
# 'def' é a palavra-chave em Python para definir uma função.

def obter_sysname_via_snmp(ip_alvo):
    """
    Esta função tenta buscar o "sysName" (nome do sistema) de um dispositivo
    na rede usando o protocolo SNMP.

    Argumentos:
        ip_alvo (str): O endereço IP do dispositivo que queremos consultar.

    Retorna:
        str: O sysName do dispositivo, se encontrado.
        None: Se não conseguir encontrar o sysName ou se ocorrer um erro.
    """
    # print(f"  [SNMP Tentativa] Verificando sysName para {ip_alvo}...") # Linha para depuração

    # 1. Cria uma "engine" SNMP. É o motor que vai processar nossa requisição.
    snmp_engine_local = SnmpEngine()

    # 2. Define a "comunidade" SNMP. Pense nisso como um grupo de acesso.
    #    'mpModel=0' significa que estamos usando SNMPv1 (uma versão mais antiga e simples).
    dados_comunidade = CommunityData(SNMP_COMMUNITY_STRING, mpModel=0)

    # 3. Define o "alvo" da nossa requisição: o IP e a porta do dispositivo.
    #    Também configuramos o timeout e as retentativas aqui.
    alvo_transporte_udp = UdpTransportTarget(
        (str(ip_alvo), SNMP_PORTA),
        timeout=SNMP_TIMEOUT_SEGUNDOS,
        retries=SNMP_RETENTATIVAS
    )

    # 4. Define o "contexto" SNMP. Para operações simples, geralmente não precisamos nos preocupar com isso.
    dados_contexto = ContextData()

    # 5. Define o "OID" (Object Identifier) que queremos buscar.
    #    O OID '1.3.6.1.2.1.1.5.0' corresponde ao sysName no padrão SNMP (MIB-II).
    #    'SNMPv2-MIB', 'sysName', 0 é uma forma mais amigável de escrever esse OID usando o pysnmp.
    oid_sysname = ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0))

    # 6. Executa o comando GET do SNMP.
    #    'next(...)' é usado porque getCmd retorna um "gerador" (um tipo especial de iterador).
    #    Estamos pedindo para pegar o próximo (e neste caso, único) resultado.
    iterador_resultado = getCmd(
        snmp_engine_local,
        dados_comunidade,
        alvo_transporte_udp,
        dados_contexto,
        oid_sysname
    )

    try:
        # Tentamos pegar o resultado da nossa consulta SNMP
        indicacao_erro, status_erro, indice_erro, variaveis_recebidas = next(iterador_resultado)

        # 7. Verifica se houve algum erro na comunicação SNMP.
        if indicacao_erro:
            # print(f"  [SNMP Falha] Indicação de erro para {ip_alvo}: {indicacao_erro}")
            return None # Se houve erro na "indicação" (ex: timeout), retorna nada.
        elif status_erro:
            # Se o dispositivo respondeu, mas com um status de erro SNMP (ex: OID não existe lá).
            # print(f"  [SNMP Falha] Status de erro para {ip_alvo}: {status_erro.prettyPrint()} em {indice_erro and variaveis_recebidas[int(indice_erro) - 1][0] or '?'}")
            return None
        else:
            # 8. Se tudo deu certo, 'variaveis_recebidas' contém a resposta.
            #    Ela é uma lista de tuplas, onde cada tupla é (OID_recebido, valor_recebido).
            #    Para um GET simples em sysName.0, esperamos uma tupla na lista.
            if variaveis_recebidas and len(variaveis_recebidas) > 0:
                # O valor do sysName é o segundo item da primeira tupla.
                objeto_sysname = variaveis_recebidas[0][1]
                # O método '.prettyPrint()' converte o valor para um formato de texto legível.
                return objeto_sysname.prettyPrint()
            else:
                # print(f"  [SNMP Falha] Nenhuma variável (sysName) retornada para {ip_alvo}.")
                return None # Não recebemos o valor esperado.

    except StopIteration:
        # Isso acontece se o 'next(iterador_resultado)' não encontrar nenhum item,
        # o que geralmente significa que não houve resposta SNMP (timeout, host não responde SNMP).
        # print(f"  [SNMP Falha] Sem resposta SNMP (StopIteration/Timeout) de {ip_alvo}.")
        return None
    except Exception as e:
        # Captura qualquer outro erro inesperado durante o processo SNMP.
        # print(f"  [SNMP Falha] Exceção inesperada para {ip_alvo}: {e}")
        return None

def testar_host_com_ping(ip_host_para_testar):
    """
    Verifica se um host (dispositivo) na rede está ativo (responde a "ping").
    Usa o comando 'ping' do sistema operacional.

    Argumentos:
        ip_host_para_testar (ipaddress.IPv4Address ou str): O IP do host a ser testado.

    Retorna:
        bool: True se o host responder ao ping, False caso contrário.
    """
    # Converte o IP para formato de texto (string), caso ainda não seja.
    ip_texto = str(ip_host_para_testar)

    # Monta o comando 'ping' que será executado.
    # As opções são específicas para Linux, como pedido pelo professor:
    # '-c 1': Enviar apenas 1 pacote de ping.
    # '-W TIMEOUT_PING_SEGUNDOS': Esperar no máximo X segundos pela resposta.
    # '-i 0.2': Intervalo de 0.2 segundos (ajuda a não sobrecarregar e ser rápido).
    comando = ['ping', '-c', '1', '-W', str(TIMEOUT_PING_SEGUNDOS), '-i', '0.2', ip_texto]

    # O bloco 'try...except' é usado para tratamento de erros.
    # Se algo der errado dentro do 'try', o Python pula para o 'except' correspondente.
    try:
        # 'subprocess.run()' executa o comando.
        # 'stdout=subprocess.DEVNULL' e 'stderr=subprocess.DEVNULL' escondem a saída normal
        # do comando ping, pois só nos interessa se ele funcionou ou não.
        # 'timeout' no subprocess.run previne que ele fique travado indefinidamente.
        resultado_comando = subprocess.run(
            comando,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=TIMEOUT_PING_SEGUNDOS + 0.5 # Um pouco mais que o timeout do ping em si.
        )
        # 'resultado_comando.returncode' é 0 se o ping foi bem-sucedido.
        return resultado_comando.returncode == 0
    except subprocess.TimeoutExpired:
        # Se o comando 'ping' demorar mais que o 'timeout' do subprocess.run.
        # print(f"  [Ping DEBUG] Timeout ao executar ping para {ip_texto}.")
        return False
    except Exception:
        # Se qualquer outro erro ocorrer ao tentar executar o ping.
        # print(f"  [Ping DEBUG] Erro ao executar ping para {ip_texto}: {e_ping}")
        return False

def scan_arp_rede_local(objeto_rede_alvo):
    """
    Realiza um scan usando o protocolo ARP para descobrir hosts na rede local.
    ARP é mais rápido que ping para redes locais. Usa a biblioteca Scapy.

    Argumentos:
        objeto_rede_alvo (ipaddress.IPv4Network): O objeto representando a rede a ser escaneada.

    Retorna:
        list: Uma lista de strings, cada uma sendo um IP ativo encontrado via ARP.
    """
    ips_ativos_via_arp = [] # Lista para guardar os IPs que responderem.
    # print(f"  [ARP DEBUG] Iniciando scan ARP para a rede {objeto_rede_alvo}...")

    # Bloco try...except para lidar com possíveis erros durante o uso do Scapy.
    try:
        # 1. Monta o pacote ARP Request.
        #    'Ether(dst="ff:ff:ff:ff:ff:ff")' cria o cabeçalho Ethernet com destino broadcast
        #    (para todos na rede local).
        #    'ARP(pdst=str(objeto_rede_alvo))' cria a parte ARP da requisição, perguntando
        #    pelos IPs dentro da 'objeto_rede_alvo'. Scapy vai gerar um request para cada IP.
        pacote_arp_requisicao = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(objeto_rede_alvo))

        # 2. Envia os pacotes e recebe as respostas.
        #    'srp' é a função do Scapy para enviar e receber pacotes na camada 2 (Ethernet).
        #    'timeout=1' espera por 1 segundo no máximo.
        #    'verbose=False' para não imprimir muita informação do Scapy na tela.
        #    Retorna duas listas: 'respondidos' (pacotes que tiveram resposta) e 'nao_respondidos'.
        lista_pacotes_respondidos, _ = srp(pacote_arp_requisicao, timeout=1, verbose=False)

        # 3. Processa as respostas.
        if lista_pacotes_respondidos:
            # print(f"  [ARP DEBUG] {len(lista_pacotes_respondidos)} respostas ARP recebidas.")
            # 'lista_pacotes_respondidos' contém tuplas (pacote_enviado, pacote_recebido).
            # Nós queremos o IP de origem ('psrc') do pacote recebido.
            for _, pacote_resposta_arp in lista_pacotes_respondidos:
                ips_ativos_via_arp.append(pacote_resposta_arp.psrc)
        # else:
            # print(f"  [ARP DEBUG] Nenhuma resposta ARP.")

    except Exception as e_arp:
        print(f"  [ARP ERRO] Falha durante o scan ARP: {e_arp}")

    # 'set(ips_ativos_via_arp)' remove duplicatas, e 'list(...)' converte de volta para lista.
    return list(set(ips_ativos_via_arp))

def scan_ping_em_paralelo(objeto_rede_alvo):
    """
    Realiza um scan de ping em múltiplos IPs da rede de forma paralela (ao mesmo tempo).
    Usa 'ThreadPoolExecutor' para gerenciar as tarefas de ping.

    Argumentos:
        objeto_rede_alvo (ipaddress.IPv4Network): O objeto da rede a ser escaneada.

    Retorna:
        list: Uma lista de strings, cada uma sendo um IP ativo encontrado via Ping.
    """
    ips_ativos_via_ping = [] # Lista para os IPs que responderem ao ping.

    # '.hosts()' retorna um gerador com todos os IPs utilizáveis dentro da rede
    # (excluindo o endereço da rede e o de broadcast).
    lista_ips_para_testar = list(objeto_rede_alvo.hosts())

    if not lista_ips_para_testar:
        # print(f"  [Ping Scan DEBUG] A rede {objeto_rede_alvo} não possui hosts para testar.")
        return [] # Se não há IPs, retorna lista vazia.

    # print(f"  [Ping Scan DEBUG] Iniciando pings para {len(lista_ips_para_testar)} IPs...")

    # 'ThreadPoolExecutor' gerencia um grupo de "trabalhadores" (threads).
    # 'max_workers' define quantos pings podem rodar simultaneamente.
    with ThreadPoolExecutor(max_workers=MAX_THREADS_SCAN_PING) as executor_de_tarefas:
        # Para cada IP na lista, submetemos a função 'testar_host_com_ping' para ser executada
        # por um dos trabalhadores do executor.
        # 'mapa_futuro_para_ip' guarda a relação entre a tarefa futura e o IP correspondente,
        # para sabermos a qual IP um resultado pertence.
        mapa_futuro_para_ip = {
            executor_de_tarefas.submit(testar_host_com_ping, ip_atual): ip_atual
            for ip_atual in lista_ips_para_testar
        }

        # 'as_completed' espera que as tarefas (pings) terminem, na ordem em que completarem.
        for futuro_da_tarefa_ping in as_completed(mapa_futuro_para_ip):
            ip_associado_ao_futuro = mapa_futuro_para_ip[futuro_da_tarefa_ping]
            try:
                # '.result()' pega o valor retornado pela função 'testar_host_com_ping' (True ou False).
                if futuro_da_tarefa_ping.result():
                    ips_ativos_via_ping.append(str(ip_associado_ao_futuro))
            except Exception:
                # Se houve algum erro ao obter o resultado da tarefa.
                # print(f"  [Ping Scan DEBUG] Erro ao processar resultado do ping para {ip_associado_ao_futuro}: {e_thread_ping}")
                pass # Ignora o erro e continua com os próximos.

    # if ips_ativos_via_ping:
        # print(f"  [Ping Scan DEBUG] {len(ips_ativos_via_ping)} IPs ativos encontrados via ping.")
    # else:
        # print(f"  [Ping Scan DEBUG] Nenhum IP ativo encontrado via ping.")

    return list(set(ips_ativos_via_ping))

def executar_scan_completo_na_rede(objeto_rede_alvo):
    """
    Orquestra o scan da rede, combinando ARP (se habilitado) e Ping.

    Argumentos:
        objeto_rede_alvo (ipaddress.IPv4Network): A rede a ser escaneada.

    Retorna:
        list: Uma lista de IPs (strings) ativos encontrados na rede.
    """
    # 'set' é usado para armazenar os IPs ativos, pois ele automaticamente evita duplicatas.
    conjunto_ips_ativos = set()

    if USAR_ARP_SCAN:
        print(f"[SCAN INFO] Iniciando Fase 1: Scan ARP para {objeto_rede_alvo}...")
        ips_do_arp = scan_arp_rede_local(objeto_rede_alvo)
        for ip_encontrado_arp in ips_do_arp:
            conjunto_ips_ativos.add(ip_encontrado_arp)
        print(f"[SCAN INFO] Fase 1 (ARP) concluída. {len(ips_do_arp)} hosts encontrados via ARP.")

    print(f"[SCAN INFO] Iniciando Fase 2: Scan Ping para {objeto_rede_alvo}...")
    ips_do_ping = scan_ping_em_paralelo(objeto_rede_alvo)
    for ip_encontrado_ping in ips_do_ping:
        conjunto_ips_ativos.add(ip_encontrado_ping)
    print(f"[SCAN INFO] Fase 2 (Ping) concluída. {len(ips_do_ping)} hosts encontrados ou confirmados via Ping.")

    total_encontrado = len(conjunto_ips_ativos)
    if total_encontrado > 0:
        print(f"[SCAN INFO] Scan total finalizado! {total_encontrado} hosts ativos únicos encontrados na rede {objeto_rede_alvo}. :)")
    else:
        print(f"[SCAN INFO] Scan total finalizado. Nenhum host ativo encontrado na rede {objeto_rede_alvo}. :(")
    
    return list(conjunto_ips_ativos) # Converte o conjunto de volta para uma lista.

# --------------------------------------------------------------------------------
# SEÇÃO 4: FUNÇÃO PARA GERENCIAR CADA CLIENTE CONECTADO
# --------------------------------------------------------------------------------

def gerenciar_conexao_cliente(socket_conexao_cliente, endereco_ip_cliente):
    """
    Esta função é executada para cada cliente que se conecta ao servidor.
    Ela recebe a requisição do cliente (CIDR), processa e envia a resposta.

    Argumentos:
        socket_conexao_cliente (socket.socket): O objeto socket para esta conexão específica com o cliente.
        endereco_ip_cliente (tuple): Uma tupla contendo o IP e a porta do cliente conectado (ex: ('192.168.1.10', 54321)).
    """
    print(f"[CONEXÃO] Cliente {endereco_ip_cliente} conectou-se!")

    # O bloco 'try...finally' garante que certas ações (como fechar o socket)
    # aconteçam mesmo que ocorram erros.
    try:
        # Loop para continuar recebendo dados do mesmo cliente até que ele desconecte
        # ou envie uma mensagem vazia.
        while True:
            # 1. Recebe dados do cliente.
            #    '.recv(1024)' tenta ler até 1024 bytes de dados.
            #    '.decode('utf-8')' converte os bytes recebidos (que é como os dados viajam na rede) para texto (string).
            #    '.strip()' remove espaços em branco extras do início e do fim do texto.
            dados_recebidos_do_cliente = socket_conexao_cliente.recv(1024).decode('utf-8').strip()

            # 2. Verifica se o cliente enviou algo.
            #    Se 'dados_recebidos_do_cliente' for uma string vazia, significa que o cliente
            #    provavelmente fechou a conexão.
            if not dados_recebidos_do_cliente:
                print(f"[CONEXÃO] Cliente {endereco_ip_cliente} enviou dados vazios ou desconectou.")
                break # Sai do loop 'while True', encerrando o tratamento para este cliente.

            print(f"[CLIENTE {endereco_ip_cliente}] Requisição recebida: '{dados_recebidos_do_cliente}'")

            # 3. Valida o formato da string CIDR recebida (ex: "192.168.1.0/24").
            #    're.compile()' cria um "objeto de expressão regular" para o padrão.
            #    '^' significa início da string, '$' significa fim da string.
            #    '(\d{1,3}\.){3}\d{1,3}' casa com um formato de IP (ex: xxx.xxx.xxx.xxx).
            #    '\/\d{1,2}' casa com uma barra seguida de 1 ou 2 dígitos (o prefixo da máscara).
            padrao_cidr_esperado = re.compile(r'^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$')
            if not padrao_cidr_esperado.match(dados_recebidos_do_cliente):
                mensagem_erro_formato = "ERRO: Formato da rede CIDR inválido. Por favor, use o formato como '192.168.1.0/24'.\n"
                # '.encode('utf-8')' converte a mensagem de texto para bytes antes de enviar.
                socket_conexao_cliente.sendall(mensagem_erro_formato.encode('utf-8'))
                continue # Volta para o início do loop 'while True' para esperar uma nova tentativa do cliente.

            # 4. Tenta converter a string CIDR em um objeto de rede Python.
            try:
                # 'ipaddress.IPv4Network()' faz essa conversão e validação.
                # 'strict=False' permite que o endereço base da rede (ex: 192.168.1.0) seja usado,
                # o que é comum na notação CIDR.
                objeto_rede_para_scan = ipaddress.IPv4Network(dados_recebidos_do_cliente, strict=False)

                mensagem_inicio_scan = f"INFO: Scan iniciado para a rede {objeto_rede_para_scan}. Aguarde os resultados...\n"
                socket_conexao_cliente.sendall(mensagem_inicio_scan.encode('utf-8'))

                # 5. Executa o scan na rede!
                lista_ips_ativos_encontrados = executar_scan_completo_na_rede(objeto_rede_para_scan)

                # 6. Envia os resultados de volta para o cliente.
                if lista_ips_ativos_encontrados:
                    mensagem_quantidade = f"RESULTADO: {len(lista_ips_ativos_encontrados)} host(s) ativo(s) encontrado(s):\n"
                    socket_conexao_cliente.sendall(mensagem_quantidade.encode('utf-8'))

                    # Para cada IP ativo encontrado...
                    for ip_ativo_str in lista_ips_ativos_encontrados:
                        # Tenta obter o sysName via SNMP para este IP.
                        sysname_do_host = obter_sysname_via_snmp(ip_ativo_str)

                        if sysname_do_host:
                            # Se o sysName foi obtido, envia "IP sysName".
                            linha_resposta_cliente = f"{ip_ativo_str} {sysname_do_host}\n"
                        else:
                            # Se não conseguiu o sysName (ou SNMP não está habilitado/configurado no alvo),
                            # envia apenas o IP, conforme o requisito do trabalho.
                            linha_resposta_cliente = f"{ip_ativo_str}\n"
                        socket_conexao_cliente.sendall(linha_resposta_cliente.encode('utf-8'))
                else:
                    # Se nenhum host ativo foi encontrado.
                    socket_conexao_cliente.sendall(b"RESULTADO: Nenhum host ativo encontrado na rede especificada.\n")
                
                # Mensagem final para esta requisição de scan específica.
                socket_conexao_cliente.sendall("INFO: Scan para esta rede concluído.\n")

            except ValueError as e_valor_ip:
                # Se 'ipaddress.IPv4Network()' não conseguir processar a string (ex: IP inválido como 999.999.9.9/24).
                mensagem_erro_ip_invalido = f"ERRO: O endereço de rede '{dados_recebidos_do_cliente}' parece ser inválido. Detalhe: {e_valor_ip}\n"
                socket_conexao_cliente.sendall(mensagem_erro_ip_invalido.encode('utf-8'))

    except ConnectionResetError:
        # Ocorre se o cliente fechar a conexão abruptamente.
        print(f"[CONEXÃO] Cliente {endereco_ip_cliente} fechou a conexão inesperadamente.")
    except Exception as e_geral_cliente:
        # Captura qualquer outro erro inesperado durante a comunicação com este cliente.
        print(f"[ERRO] Erro inesperado com o cliente {endereco_ip_cliente}: {e_geral_cliente}")
    finally:
        # Este bloco 'finally' é executado SEMPRE, não importa se houve erro ou não.
        # É importante para garantir que a conexão com o cliente seja fechada corretamente.
        print(f"[CONEXÃO] Encerrando conexão com o cliente {endereco_ip_cliente}.")
        socket_conexao_cliente.close()

# --------------------------------------------------------------------------------
# SEÇÃO 5: FUNÇÃO PRINCIPAL PARA INICIAR O SERVIDOR
# --------------------------------------------------------------------------------

def iniciar_servidor_principal():
    """
    Configura e inicia o servidor TCP principal que vai escutar por conexões de clientes.
    """
    # 1. Cria o objeto socket principal do servidor.
    #    'socket.AF_INET' especifica que usaremos endereçamento IPv4.
    #    'socket.SOCK_STREAM' especifica que usaremos o protocolo TCP (orientado à conexão).
    socket_escuta_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 2. Configura uma opção do socket: SO_REUSEADDR.
    #    Isso permite que o servidor reinicie e use a mesma porta rapidamente após ser fechado,
    #    evitando o erro "Address already in use" (Endereço já em uso).
    socket_escuta_servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # 3. Associa (ou "liga" - bind) o socket a um endereço IP e porta específicos.
    #    '0.0.0.0' significa que o servidor vai escutar em todas as interfaces de rede
    #    disponíveis no computador (ex: Wi-Fi, Ethernet).
    #    'PORTA_SERVIDOR' é a porta que definimos lá no início.
    try:
        socket_escuta_servidor.bind(('0.0.0.0', PORTA_SERVIDOR))
        print(f"[SERVIDOR] Ligado com sucesso ao endereço 0.0.0.0 na porta {PORTA_SERVIDOR}.")
    except OSError as e_bind:
        print(f"[SERVIDOR ERRO] Falha ao tentar ligar o servidor à porta {PORTA_SERVIDOR}. Detalhe: {e_bind}")
        print("[SERVIDOR ERRO] Verifique se a porta já está sendo usada por outro programa ou se você tem permissão.")
        return # Sai da função, pois o servidor não pode continuar.

    # 4. Coloca o socket em modo de escuta, pronto para aceitar conexões.
    #    O número '5' (chamado de backlog) é o número máximo de conexões que podem
    #    ficar na fila esperando para serem aceitas pelo servidor.
    socket_escuta_servidor.listen(5)
    print(f"[SERVIDOR] Escutando por conexões de clientes na porta {PORTA_SERVIDOR}...")

    # 5. Loop principal do servidor: fica continuamente aceitando novas conexões de clientes.
    try:
        while True: # Loop infinito, até que o servidor seja interrompido (ex: Ctrl+C).
            # '.accept()' bloqueia a execução e espera até que um cliente tente se conectar.
            # Quando um cliente conecta, '.accept()' retorna duas coisas:
            #  - 'socket_para_este_cliente': um NOVO objeto socket, específico para a comunicação com ESTE cliente.
            #  - 'endereco_deste_cliente': uma tupla com o IP e a porta do cliente.
            socket_para_este_cliente, endereco_deste_cliente = socket_escuta_servidor.accept()

            # Para cada cliente que se conecta, criamos uma nova "thread".
            # Uma thread é como um sub-programa que roda em paralelo com o resto.
            # Isso permite que o servidor converse com vários clientes ao mesmo tempo,
            # sem que um cliente tenha que esperar o outro terminar.
            # 'target=gerenciar_conexao_cliente' diz qual função a thread vai executar.
            # 'args=(...)' passa os argumentos para essa função.
            thread_para_cliente_novo = threading.Thread(
                target=gerenciar_conexao_cliente,
                args=(socket_para_este_cliente, endereco_deste_cliente)
            )
            # 'daemon=True' significa que se o programa principal do servidor fechar,
            # todas essas threads de clientes também fecharão automaticamente.
            thread_para_cliente_novo.daemon = True
            thread_para_cliente_novo.start() # Inicia a execução da thread.

    except KeyboardInterrupt:
        # Se o usuário pressionar Ctrl+C no terminal, o programa é interrompido.
        print("\n[SERVIDOR] Solicitação de desligamento recebida (Ctrl+C). Encerrando...")
    except Exception as e_loop_servidor:
        print(f"[SERVIDOR ERRO] Um erro inesperado ocorreu no loop principal do servidor: {e_loop_servidor}")
    finally:
        # Garante que o socket de escuta principal do servidor seja fechado ao sair.
        print("[SERVIDOR] Fechando o socket de escuta principal.")
        socket_escuta_servidor.close()

# --------------------------------------------------------------------------------
# SEÇÃO 6: PONTO DE ENTRADA DO SCRIPT (QUANDO EXECUTADO DIRETAMENTE)
# --------------------------------------------------------------------------------
# A linha 'if __name__ == "__main__":' é um padrão em Python.
# O código dentro deste 'if' só será executado se este arquivo
# ('servidor_scan_detalhado.py') for rodado diretamente (ex: 'python servidor_scan_detalhado.py').
# Se ele for importado como um módulo por outro script, esta parte não roda.
if __name__ == "__main__":
    # Pequeno aviso sobre o Scapy, já que ele pode precisar de permissões especiais no Linux.
    if platform.system() != "Linux" and USAR_ARP_SCAN:
        print("[AVISO INICIAL] O Scan ARP com Scapy é mais eficaz no Linux e pode requerer privilégios de administrador (root/sudo).")
        print("[AVISO INICIAL] Se encontrar problemas com o ARP Scan em outros sistemas, tente executar como administrador ou defina USAR_ARP_SCAN = False no código.")

    # Chama a função para iniciar nosso servidor!
    iniciar_servidor_principal()