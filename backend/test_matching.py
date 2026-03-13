import pandas as pd
from vuln_logic import prepare_new, prepare_hist, build_key_ot

# Simulated data mimicking the screenshot
# The issue is that the SAME vulnerability is both "Mitigadas" and "Nuevas".
# This happens if it's in history as open, and in new scan, but keys don't match.

data_new = {
    "Risk": ["Medium", "Medium"],
    "Host": ["srvwebapp2.acuacar.corp", "srvwebapp2.acuacar.corp"],
    "NetBios": ["SRVWEBAPP2", "SRVWEBAPP2"],
    "IP Address": ["10.3.11.26", "10.3.11.26"],
    "Port": [8080, 8080],
    "Name": ["Apache Tomcat 9.0.0.M1 < 9.0.113 multiple vulnerabilities", "Apache Tomcat 9.0.83 < 9.0.115"]
}
df_new = pd.DataFrame(data_new)

data_hist = {
    "Riesgo": ["Medium", "Medium"],
    "Host": ["SRVWEBAPP2", "SRVWEBAPP2"],
    "NetBios": ["SRVWEBAPP2", "SRVWEBAPP2"],
    "IP Address": ["10.3.11.26", "10.3.11.26"],
    "Port": [8080, 8080],
    "Name": ["Apache Tomcat 9.0.0.M1 < 9.0.113 multiple vulnerabilities", "Apache Tomcat 9.0.83 < 9.0.115"],
    "Mitigado": ["", ""] # Open in history
}
df_hist = pd.DataFrame(data_hist)

cols_new = {"risk": "Risk", "host": "Host", "ip": "IP Address", "port": "Port", "name": "Name", "netbios": "NetBios"}
cols_hist = {"risk": "Riesgo", "host": "Host", "ip": "IP Address", "port": "Port", "name": "Name", "netbios": "NetBios", "mitigado": "Mitigado"}

prep_new = prepare_new(df_new, "medium", cols_new, tipo="ot")
prep_hist = prepare_hist(df_hist, "medium", cols_hist, tipo="ot")

print("--- NEW ---")
print(prep_new[["IP Address", "Host", "NetBios", "Port", "Name", "key_hash", "key_hash_nb"]])

print("\n--- HIST ---")
print(prep_hist[["IP Address", "Host", "NetBios", "Port", "Name", "key_hash", "key_hash_nb"]])

# Simulate classification logic
set_hist_open = set(prep_hist["key_hash"].astype(str)) | set(prep_hist["key_hash_nb"].astype(str))

def classify(row):
    k = str(row["key_hash"])
    k_nb = str(row["key_hash_nb"])
    if k in set_hist_open or k_nb in set_hist_open:
        return "P (Persistent)"
    return "N (New)"

prep_new["Class"] = prep_new.apply(classify, axis=1)
print("\n--- CLASSIFICATION ---")
print(prep_new[["Name", "Class"]])
