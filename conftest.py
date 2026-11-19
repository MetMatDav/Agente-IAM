# Vacio a proposito: la presencia de un conftest.py en la raiz hace que
# pytest agregue esta carpeta a sys.path, y con eso los tests pueden
# importar `agente_iam` sin instalar el paquete.
