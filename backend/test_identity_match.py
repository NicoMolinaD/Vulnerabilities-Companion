import io
import pandas as pd
from vuln_logic import compare_vulnerabilities

def test_ot():
    print("\n--- Testing OT Classification ---")
    nuevo_csv = """Host,IP Address,Port,Name,Risk,Plugin Output
srv1,10.0.0.1,80,Vuln Exact,Medium,Output Exact
srv1,10.0.0.2,80,Vuln ID Same,Medium,Output Same
srv1,10.0.0.3,80,Vuln ID Diff,Medium,Output New
"""
    hist_csv = """Host,IP Address,Puerto,Vulnerabilidad,Tipo de riesgo,Mitigado,Modo del escaneo,Output
srv1,10.0.0.1,80,Vuln Exact,Medium,,Auto,Output Exact
srv1,10.0.0.2,80,Vuln ID Same,Medium,,Auto,Output Same
srv1,10.0.0.3,80,Vuln ID Diff,Medium,,Auto,Output Old
"""
    _, summary = compare_vulnerabilities(nuevo_csv.encode('utf-8'), "n.csv", hist_csv.encode('utf-8'), "h.csv", tipo="ot")
    print(f"Summary: Nuevas={summary['nuevas']}, Persistentes={summary['persistentes']}, Actualizadas={summary['actualizadas']}")
    for d in summary['detalles']:
        if d['status'] != 'Mitigadas':
            print(f"[{d['status']}] {d['name']} | Old Output: {d.get('old_output')}")

def test_infra():
    print("\n--- Testing Infra Classification ---")
    nuevo_csv = """Host,IP Address,Port,Name,Risk,Plugin Output
srvA,10.1.1.1,443,Infra Exact,Medium,Out A
srvA,10.1.1.2,443,Infra ID Same,Medium,Out B
srvA,10.1.1.3,443,Infra ID Diff,Medium,Out New
"""
    hist_csv = """Host,IP Address,Port,Name,Risk,Mitigado,Plugin Output
srvA,10.1.1.1,443,Infra Exact,Medium,,Out A
srvA,10.1.1.2,443,Infra ID Same,Medium,,Out B
srvA,10.1.1.3,443,Infra ID Diff,Medium,,Out Old
"""
    _, summary = compare_vulnerabilities(nuevo_csv.encode('utf-8'), "n.csv", hist_csv.encode('utf-8'), "h.csv", tipo="infra")
    print(f"Summary: Nuevas={summary['nuevas']}, Persistentes={summary['persistentes']}, Actualizadas={summary['actualizadas']}")
    for d in summary['detalles']:
        if d['status'] != 'Mitigadas':
            print(f"[{d['status']}] {d['name']} | Old Output: {d.get('old_output')}")

if __name__ == "__main__":
    test_ot()
    test_infra()
