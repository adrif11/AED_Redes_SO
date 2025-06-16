import sys
import platform

print("--- Verificação do Ambiente Python ---")
print(f"Versão do Python: {sys.version}")
print(f"Executável Python (sys.executable): {sys.executable}")

print("\nCaminhos onde este Python procura por módulos (sys.path):")
for path in sys.path:
    print(f"- {path}")

print("\n--- Testando Importação do PureSNMP ---")
try:
    import puresnmp
    print("\nSUCESSO! Biblioteca 'puresnmp' foi encontrada.")
    print(f"Localização do puresnmp: {puresnmp.__file__}")
except ImportError:
    print("\nFALHA! Biblioteca 'puresnmp' NÃO foi encontrada por este interpretador Python.")

print("-" * 40)
