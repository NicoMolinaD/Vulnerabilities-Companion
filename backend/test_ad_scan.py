import pandas as pd
from vuln_logic import resolve_cols, HIST_COLS_AD, prepare_hist

def test_ad_column_resolution():
    # Simulated historical data with the special AD column
    data = {
        "Vulnerabilidad *Directorio Activo*": ["AD Starter Scan - Null sessions", "AD Starter Scan - Non-Expiring Account Password"],
        "Vulnerabilidad": ["Generic Vuln Name 1", "Generic Vuln Name 2"],
        "Mitigado": ["", "Mitigado"],
        "Riesgo": ["High", "Medium"],
        "Host IP": ["10.3.11.10", "10.3.11.10"],
        "Host Nombre": ["srvaz03.acuacar.corp", "srvaz03.acuacar.corp"],
        "Puerto": [636, 636],
        "CVSS": [7.1, 4.1]
    }
    df = pd.DataFrame(data)
    
    # Resolve columns using the new AD mapping
    cols = resolve_cols(df, HIST_COLS_AD)
    print(f"Resolved columns: {cols}")
    
    # Verify name column resolution
    assert cols["name"] == "Vulnerabilidad *Directorio Activo*"
    
    # Prepare historical data
    prep_hist = prepare_hist(df, "medium", cols, tipo="ad")
    
    print("\n--- PREPARED HIST ---")
    print(prep_hist[["Name", "IP Address", "Host", "Port", "Risk_EN", "Mitigado"]])
    
    # Verify that the AD names are used
    assert prep_hist.iloc[0]["Name"] == "AD Starter Scan - Null sessions"
    assert prep_hist.iloc[1]["Name"] == "AD Starter Scan - Non-Expiring Account Password"
    
    print("\nTest passed successfully!")

if __name__ == "__main__":
    test_ad_column_resolution()
