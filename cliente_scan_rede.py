# Nome do arquivo: cliente_apresentacao.py
import socket
import sys

# Verifica se o endereço do servidor e o CIDR foram passados como argumentos
if len(sys.argv) != 3:
    print("Uso: python3 cliente_apresentacao.py <ip_do_servidor> <rede_cidr>")
    print("Exemplo: python3 cliente_apresentacao.py 127.0.0.1 192.168.1.0/24")
    sys.exit(1)

HOST_DO_SERVIDOR = sys.argv[1]
CIDR_PARA_SCAN = sys.argv[2]
PORTA_DO_SERVIDOR = 35640

def executar_cliente():
    print("--- Cliente de Scan de Rede ---")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            print(f"Conectando ao servidor em {HOST_DO_SERVIDOR}:{PORTA_DO_SERVIDOR}...")
            sock.connect((HOST_DO_SERVIDOR, PORTA_DO_SERVIDOR))
            print("Conexão estabelecida. Enviando requisição de scan...")
            
            sock.sendall(CIDR_PARA_SCAN.encode('utf-8'))
            
            print("\n--- Aguardando resposta do Servidor ---")
            # Loop para receber a resposta completa do servidor
            while True:
                dados_recebidos = sock.recv(1024)
                if not dados_recebidos:
                    break # Servidor fechou a conexão
                print(dados_recebidos.decode('utf-8'), end='')

        except ConnectionRefusedError:
            print(f"ERRO DE CONEXÃO: Conexão recusada. O servidor está rodando?")
        except Exception as e:
            print(f"ERRO INESPERADO: {e}")
        finally:
            print("\n--- Fim da Sessão ---")

if __name__ == "__main__":
    executar_cliente()
