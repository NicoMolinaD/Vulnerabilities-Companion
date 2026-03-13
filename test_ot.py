import pandas as pd
from backend.vuln_logic import compare_vulnerabilities

with open("csves/nuevo_ot.csv", "rb") as f1, open("csves/hist_ot.csv", "rb") as f2:
    n = f1.read()
    h = f2.read()

out = compare_vulnerabilities(n, "nuevo_ot.csv", h, "hist_ot.csv", tipo="ot")

xls = pd.ExcelFile(out)
df_res = pd.read_excel(xls, "Resumen")
print(df_res)
