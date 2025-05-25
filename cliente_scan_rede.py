# --------------------------------------------------------------------------------
# SEÇÃO 1: IMPORTAÇÕES DE "CAIXAS DE FERRAMENTAS" (MÓDULOS)
# --------------------------------------------------------------------------------
import socket # Caixa de ferramentas para comunicação em rede.

# --------------------------------------------------------------------------------
# SEÇÃO 2: CONFIGURAÇÕES GLOBAIS DO NOSSO CLIENTE
# --------------------------------------------------------------------------------
# Endereço IP do servidor ao qual queremos nos conectar.
# '127.0.0.1' significa "este mesmo computador" (localhost).
HOST_DO_SERVIDOR = '127.0.0.1'
# Porta de comunicação do servidor. Deve ser a MESMA porta que o servidor está escutando.
PORTA_DO_SERVIDOR = 35640 # Igual à PORTA_SERVIDOR no script do servidor.

# --------------------------------------------------------------------------------
# SEÇÃO 3: FUNÇÃO PRINCIPAL DO CLIENTE
# --------------------------------------------------------------------------------
def executar_programa_cliente():
    """
    Função principal que executa a lógica do cliente: conectar ao servidor,
    enviar requisições de scan e exibir as respostas.
    """
    print("--- Cliente de Scan de Rede ---")

    # 1. Cria o objeto socket do cliente (o "telefone" do cliente).
    #    AF_INET para endereçamento IPv4, SOCK_STREAM para protocolo TCP.
    socket_para_cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # O bloco 'try...except...finally' serve para tratamento de erros.
    # O Python vai "tentar" (try) executar o código. Se um erro acontecer, ele pula
    # para o bloco 'except' correspondente. O bloco 'finally' SEMPRE é executado no final,
    # tenha ocorrido erro ou não (bom para fechar coisas como sockets).
    try:
        # 2. Tenta se conectar ao servidor.
        print(f"Tentando conectar ao servidor em {HOST_DO_SERVIDOR} na porta {PORTA_DO_SERVIDOR}...")
        # '.connect()' recebe uma "tupla" (um par de valores) com o IP e a porta do servidor.
        socket_para_cliente.connect((HOST_DO_SERVIDOR, PORTA_DO_SERVIDOR))
        print("Conexão com o servidor estabelecida com sucesso! :)")

        # 3. Loop principal do cliente: permite que o usuário faça vários pedidos.
        while True: # Loop infinito, só sai se o usuário digitar 'sair' ou se der um erro grave.
            # Pede para o usuário digitar a rede que ele quer escanear.
            # 'input(...)' mostra a mensagem e espera o usuário digitar algo e apertar Enter.
            # '.strip()' remove espaços em branco do começo ou do fim do que foi digitado.
            cidr_digitado_pelo_usuario = input(
                "\nDigite a rede no formato CIDR (ex: 192.168.1.0/24) ou 'sair' para fechar o cliente: "
            ).strip()

            if not cidr_digitado_pelo_usuario: # Se o usuário não digitou nada (string vazia)...
                print("Você não digitou nada. Tente novamente ou digite 'sair'.")
                continue # 'continue' pula o resto do código dentro do loop e volta para o começo do 'while'.

            # '.lower()' converte o texto para minúsculas, para aceitar "sair", "Sair", "SAIR", etc.
            if cidr_digitado_pelo_usuario.lower() == 'sair':
                print("Ok, encerrando o cliente...")
                break # 'break' interrompe o loop 'while True' e o programa continua depois dele.

            # 4. Envia a string CIDR para o servidor.
            try:
                # '.encode('utf-8')' converte o texto (string) para bytes, que é como os dados
                # viajam pela rede. 'utf-8' é um padrão de codificação de caracteres comum.
                # '.sendall()' tenta enviar TODOS os bytes de uma vez.
                socket_para_cliente.sendall(cidr_digitado_pelo_usuario.encode('utf-8'))
            except Exception as e_send: # Se der erro ao tentar enviar...
                print(f"ERRO ao enviar dados para o servidor: {e_send}. A conexão pode ter sido perdida.")
                break # Sai do loop principal do cliente, pois não dá pra continuar.

            # 5. Recebe e exibe a resposta do servidor.
            print("\n--- Resposta do Servidor ---")
            resposta_completa_servidor = "" # String vazia para "juntar" os pedaços da resposta.
            try:
                # Loop para continuar recebendo dados do servidor até que ele pare de enviar
                # ou até que uma mensagem de fim de scan seja detectada.
                while True:
                    # '.recv(4096)' tenta ler até 4096 bytes (um "pedaço" ou "chunk") da conexão.
                    # Se o servidor não tiver nada para enviar ou fechar a conexão, retorna bytes vazios.
                    chunk_de_dados_recebidos = socket_para_cliente.recv(4096)
                    if not chunk_de_dados_recebidos: # Se não recebeu nada...
                        # print("INFO: Conexão aparentemente fechada pelo servidor ou sem mais dados.") # Opcional
                        break # Sai do loop de recebimento.

                    # Converte os bytes recebidos de volta para texto.
                    texto_do_chunk = chunk_de_dados_recebidos.decode('utf-8')
                    # 'print(..., end='')' mostra o texto na tela. 'end=''' evita que o print
                    # adicione uma nova linha automaticamente, para que a formatação da resposta
                    # do servidor (que já pode ter quebras de linha \n) fique correta.
                    print(texto_do_chunk, end='')
                    # Adiciona o pedaço recebido à resposta completa, para podermos checar por mensagens de fim.
                    resposta_completa_servidor += texto_do_chunk

                    # Verifica se alguma das mensagens que indicam o fim da resposta para ESTE scan
                    # já apareceu no que recebemos até agora.
                    if "INFO: Scan para esta rede concluído." in resposta_completa_servidor or \
                       "ERRO:" in resposta_completa_servidor or \
                       "RESULTADO: Nenhum host ativo encontrado" in resposta_completa_servidor:
                        break # Sai do loop de recebimento, pois este scan específico terminou.
                
                # Só para garantir que o cursor vá para a próxima linha no console se a resposta não terminou com \n.
                if not resposta_completa_servidor.endswith('\n') and resposta_completa_servidor:
                    print()

            except ConnectionResetError: # Se o servidor fechar a conexão de forma abrupta.
                print("ERRO: A conexão com o servidor foi perdida (reset).")
                break # Sai do loop principal do cliente.
            except Exception as e_recv: # Qualquer outro erro ao receber dados.
                print(f"ERRO ao receber dados do servidor: {e_recv}")
                break # Sai do loop principal do cliente.
            
            print("--------------------------") # Linha para separar as respostas.

    except ConnectionRefusedError: # Se o servidor não estiver rodando ou recusar a conexão.
        print(f"ERRO DE CONEXÃO: Não foi possível conectar ao servidor em {HOST_DO_SERVIDOR}:{PORTA_DO_SERVIDOR}.")
        print("Verifique se o script do servidor está em execução e se o firewall não está bloqueando.")
    except socket.timeout: # Se a tentativa de conexão demorar muito (timeout).
        print("ERRO DE CONEXÃO: Timeout - a tentativa de conexão demorou muito.")
    except Exception as e_geral_cliente: # Qualquer outro erro inesperado no cliente.
        print(f"ERRO INESPERADO NO CLIENTE: {e_geral_cliente}")
    finally: # Bloco que SEMPRE é executado, não importa se houve erro ou não.
        print("\n--- Fim da Sessão do Cliente ---")
        print("Fechando a conexão com o servidor. Até a próxima! （￣︶￣）↗　")
        socket_para_cliente.close() # Fecha o "telefone" do cliente.

# --------------------------------------------------------------------------------
# SEÇÃO 4: PONTO DE ENTRADA DO SCRIPT (QUANDO EXECUTADO DIRETAMENTE)
# --------------------------------------------------------------------------------
# Esta parte só roda se você executar este arquivo diretamente (ex: python nome_do_arquivo.py)
if __name__ == "__main__":
    # Chama a função principal para executar o cliente.
    executar_programa_cliente()