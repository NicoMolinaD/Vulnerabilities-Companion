import io
import pandas as pd
from vuln_logic import compare_vulnerabilities

# Create mock CSV
nuevo_csv = """Host,IP Address,Port,Name,Risk
srvwebapp2.acuacar.corp,10.3.11.26,8080,Apache Tomcat 9.0.0.M1 < 9.0.113 multiple vulnerabilities,Medium
srvwebapp2.acuacar.corp,10.3.11.26,8080,Apache Tomcat 9.0.83 < 9.0.115,Medium
"""

hist_csv = """Host,IP Address,Puerto,Vulnerabilidad,Tipo de riesgo,Mitigado,Modo del escaneo
SRVWEBAPP2,10.3.11.26,8080,Apache Tomcat 9.0.0.M1 < 9.0.113 multiple vulnerabilities,Medium,,Auto
SRVWEBAPP2,10.3.11.26,8080,Apache Tomcat 9.0.83 < 9.0.115,Medium,,Auto
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

print(summary)
