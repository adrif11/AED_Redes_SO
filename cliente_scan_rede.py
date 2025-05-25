import socket # Para comunicação de rede.

# Configurações para conectar ao servidor.
HOST_SERVIDOR = '127.0.0.1'  # IP do servidor (localhost).
PORTA_SERVIDOR = 35640      # Porta do servidor (deve ser a mesma usada pelo servidor).

def executar_cliente():
    """
    Função principal do cliente.
    Conecta ao servidor, envia o CIDR para scan e exibe a resposta.
    """
    # Cria o socket do cliente.
    socket_cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Tenta se conectar ao servidor.
        print(f"Tentando conectar ao servidor em {HOST_SERVIDOR}:{PORTA_SERVIDOR}...")
        socket_cliente.connect((HOST_SERVIDOR, PORTA_SERVIDOR))
        print("Conectado ao servidor com sucesso! :)")

        # Loop para permitir múltiplos scans ou sair.
        while True:
            # Solicita ao usuário a rede CIDR para scan.
            cidr_scan_usuario = input("Digite a rede CIDR (ex: 192.168.1.0/24) ou 'sair' para fechar: ")

            if not cidr_scan_usuario:
                print("Entrada vazia. Por favor, digite um CIDR ou 'sair'.")
                continue
            
            if cidr_scan_usuario.lower() == 'sair':
                print("Desconectando...")
                break 

            # Envia o CIDR para o servidor.
            socket_cliente.sendall(cidr_scan_usuario.encode('utf-8'))

            print("\n--- Resposta do Servidor ---")
            # Loop para receber a resposta do servidor.
            while True:
                # Recebe dados em partes (chunks).
                chunk_dados_recebidos = socket_cliente.recv(1024)
                if not chunk_dados_recebidos:
                    # Servidor fechou a conexão ou terminou de enviar para esta requisição.
                    break 
                
                resposta_servidor_texto = chunk_dados_recebidos.decode('utf-8')
                print(resposta_servidor_texto, end='') # end='' evita nova linha extra.

                # Condições para interromper o recebimento para o scan atual.
                if "Scan para esta rede concluído." in resposta_servidor_texto or \
                   "ERRO:" in resposta_servidor_texto or \
                   "Nenhum host ativo encontrado nesta rede." in resposta_servidor_texto:
                    break
            print("\n--------------------------\n")

    except ConnectionRefusedError:
        print(f"ERRO: Conexão recusada. O servidor em {HOST_SERVIDOR}:{PORTA_SERVIDOR} está ativo?")
        print("Verifique se o script do servidor está em execução.")
    except socket.timeout:
        print("ERRO: Timeout - A conexão ou resposta demorou demais.")
    except Exception as e:
        print(f"ERRO inesperado: {e}")
    finally:
        # Fecha o socket do cliente.
        print("Fechando o cliente. （￣︶￣）↗　")
        socket_cliente.close()

# Executa a função principal do cliente se o script for rodado diretamente.
if __name__ == "__main__":
    executar_cliente()