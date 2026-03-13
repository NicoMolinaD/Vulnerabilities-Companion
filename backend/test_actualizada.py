import io
import pandas as pd
from vuln_logic import compare_vulnerabilities

# Create mock CSV with different outputs
nuevo_csv = """Host,IP Address,Port,Name,Risk,Plugin Output
srvwebapp2.acuacar.corp,10.3.11.26,8080,Vulnerability A,Medium,New Output text
srvwebapp2.acuacar.corp,10.3.11.26,8081,Vulnerability B,Medium,Same Output
"""

hist_csv = """Host,IP Address,Puerto,Vulnerabilidad,Tipo de riesgo,Mitigado,Modo del escaneo,Output
SRVWEBAPP2,10.3.11.26,8080,Vulnerability A,Medium,,Auto,Old Output text
SRVWEBAPP2,10.3.11.26,8081,Vulnerability B,Medium,,Auto,Same Output
"""

# Call compare vulnerabilities
nuevo_bytes = nuevo_csv.encode('utf-8')
hist_bytes = hist_csv.encode('utf-8')

excel_bytes, summary = compare_vulnerabilities(
    nuevo_content=nuevo_bytes,
    nuevo_filename="nuevo.csv",
    historico_content=hist_bytes,
    historico_filename="historico.csv",
    tipo="ot"
)

print(f"Nuevas: {summary['nuevas']}")
print(f"Persistentes: {summary['persistentes']}")
print(f"Actualizadas: {summary['actualizadas']}")

for detail in summary['detalles']:
    if detail['status'] != 'Mitigadas':
        status = detail['status']
        name = detail['name']
        old_out = detail.get('old_output')
        new_out = detail.get('plugin_output')
        print(f"Status: {status}, Name: {name}, Old Output: {old_out}, New Output: {new_out}")
