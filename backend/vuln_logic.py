# -*- coding: utf-8 -*-
"""
Lógica de comparación de vulnerabilidades.
Adaptación de vuln_compare.py para procesamiento en memoria.
"""

import hashlib
import io
import ipaddress
import re
import unicodedata
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import logging
import pandas as pd

logger = logging.getLogger("vuln_compare")



# -----------------------------
# Normalización base
# -----------------------------
def strip_accents(s: str) -> str:
    s = unicodedata.normalize("NFKD", s)
    s = unicodedata.normalize("NFKD", s)
    return "".join(ch for ch in s if not unicodedata.combining(ch))


def clean_host_url(x: object) -> str:
    """Elimina protocolo y slash final de hosts/URLs."""
    if x is None or (isinstance(x, float) and pd.isna(x)):
        return ""
    s = strip_accents(str(x)).strip().lower()
    s = s.replace("https://", "").replace("http://", "")
    return s.rstrip("/")

def normalize_app_name(x: object) -> str:
    """Normaliza el nombre de la app ordenando palabras (Acuacar web == Web Acuacar)."""
    if x is None or (isinstance(x, float) and pd.isna(x)):
        return ""
    s = strip_accents(str(x)).strip().lower()
    # Remover puntuación básica
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    words = sorted([w for w in s.split() if w])
    return " ".join(words)

def normalize_output_robust(x: object) -> str:
    """Normaliza el output ignorando variaciones de idioma y formato básicas."""
    if x is None or (isinstance(x, float) and pd.isna(x)):
        return ""
    s = strip_accents(str(x)).strip().lower()
    
    # Remover encabezados comunes en ES/EN que no son evidencia técnica
    s = s.replace("el servidor remoto presenta un certificado ssl/tls caducado", "")
    s = s.replace("the remote server presents an expired ssl/tls certificate", "")
    
    # Remover duraciones variables en paréntesis (ej. "expired since 6 months...", "expira en...")
    s = re.sub(r"\(expired since [^)]+\)", "", s)
    s = re.sub(r"\(expira en [^)]+\)", "", s)
    
    # Remover caracteres no alfanuméricos y colapsar espacios
    s = re.sub(r"[^a-z0-9]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s



def norm_col(s: object) -> str:
    if s is None or (isinstance(s, float) and pd.isna(s)):
        return ""
    x = strip_accents(str(s)).strip().lower()
    x = re.sub(r"[^a-z0-9]+", "", x)
    return x


def build_col_lookup(df: pd.DataFrame) -> Dict[str, str]:
    out = {}
    for c in df.columns:
        k = norm_col(c)
        if k and k not in out:
            out[k] = c
    return out


def pick_col(lookup: Dict[str, str], candidates: List[str]) -> Optional[str]:
    for cand in candidates:
        k = norm_col(cand)
        if k in lookup:
            return lookup[k]
    return None


# -----------------------------
# Lectura de archivos desde bytes
# -----------------------------
def read_csv_from_bytes(content: bytes) -> pd.DataFrame:
    encs = ["utf-8-sig", "utf-8", "latin1"]
    last_error = None
    for enc in encs:
        for sep in (None, ";", ","):
            try:
                if sep is None:
                    return pd.read_csv(io.BytesIO(content), sep=None, engine="python", encoding=enc)
                return pd.read_csv(io.BytesIO(content), sep=sep, engine="python", encoding=enc)
            except Exception as e:
                last_error = e
    raise RuntimeError(f"No se pudo leer CSV. Error: {last_error}")


def read_excel_from_bytes(content: bytes, sheet: Optional[str] = None) -> pd.DataFrame:
    try:
        xls = pd.ExcelFile(io.BytesIO(content), engine="openpyxl")
    except Exception as e:
        raise RuntimeError(f"No se pudo abrir Excel: {e}")

    if sheet is None:
        return pd.read_excel(io.BytesIO(content), sheet_name=xls.sheet_names[0], engine="openpyxl")

    if sheet.isdigit():
        idx = int(sheet)
        if idx < 0 or idx >= len(xls.sheet_names):
            raise ValueError(f"Sheet {sheet} fuera de rango. Hojas: {xls.sheet_names}")
        return pd.read_excel(io.BytesIO(content), sheet_name=xls.sheet_names[idx], engine="openpyxl")

    if sheet not in xls.sheet_names:
        raise ValueError(f"Sheet '{sheet}' no existe. Hojas: {xls.sheet_names}")
    return pd.read_excel(io.BytesIO(content), sheet_name=sheet, engine="openpyxl")


def read_table_from_bytes(content: bytes, filename: str, sheet: Optional[str] = None) -> pd.DataFrame:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in ["xlsx", "xlsm", "xls"]:
        return read_excel_from_bytes(content, sheet)
    if ext in ["csv", "txt"]:
        return read_csv_from_bytes(content)
    raise ValueError(f"Formato no soportado: {filename}. Usa .xlsx o .csv")


def drop_header_like_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Elimina filas que parecen encabezados repetidos."""
    col_norm = {c: norm_col(c) for c in df.columns}

    def is_headerish(row) -> bool:
        hits = 0
        for c in df.columns:
            v = row[c]
            if v is None or (isinstance(v, float) and pd.isna(v)):
                continue
            if norm_col(v) == col_norm[c]:
                hits += 1
        return hits >= 3

    mask = df.apply(is_headerish, axis=1)
    return df[~mask].copy()


# -----------------------------
# Normalización de riesgo / filtros
# -----------------------------
RISK_ORDER = {"medium": 1, "high": 2, "critical": 3}
RISK_EN_TO_ES = {"medium": "medio", "high": "alto", "critical": "critico"}


def normalize_risk_to_en(v: object) -> Optional[str]:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return None
    s = strip_accents(str(v)).strip().lower()
    s = s.replace("tipo de riesgo", "").replace("riesgo", "").strip()

    if s in ["critical", "critico", "crítico", "crit"]:
        return "critical"
    if s in ["high", "alto"]:
        return "high"
    if s in ["medium", "medio", "med"]:
        return "medium"

    if "crit" in s:
        return "critical"
    if "alto" in s or "high" in s:
        return "high"
    if "medio" in s or "medium" in s or "med" in s:
        return "medium"

    return None


def risk_passes_min(risk_en: Optional[str], min_risk_en: str) -> bool:
    if not risk_en:
        return False
    return RISK_ORDER.get(risk_en, 0) >= RISK_ORDER[min_risk_en]


def is_blank_mitigado(v: object, tipo: str = "infra") -> bool:
    """
    Retorna True si la vulnerabilidad está ABIERTA.
    """
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return True
    s = str(v).strip().lower()
    if s == "":
        return True
    
    if tipo == "ot":
        # En OT, solo si dice explícitamente que está mitigado es Falso (No Abierto)
        # Todo lo demás (abierto, no, vacío, pend, etc) es True (Abierto)
        if s in ["mitigado", "mitigada", "si", "yes", "1", "true", "mitigated", "cerrado"]:
            return False
        return True
    else:
        # Lógica para Infra/Apps
        # Si contiene "mitigado", "si", "yes", "1", es mitigado (False)
        if any(x in s for x in ["mitigado", "mitigada", "si", "yes"]):
            return False
        if s in ["1"]:
            return False
            
        # Todo lo demás que parezca abierto o nuevo
        return True


# -----------------------------
# Clave única robusta
# -----------------------------
import html

def normalize_ip_only(v: object) -> str:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return ""
    s = str(v).strip().lower()
    # Extraer IPv4 (patrón simple)
    m4 = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", s)
    if m4:
        return m4.group(1)
    # Extraer IPv6 (patrón simple sin backtracking complejo)
    m6 = re.search(r"([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})+)", s)
    if m6:
        return m6.group(1)
    # Si no hay match con regex, al menos limpiar espacios
    return re.sub(r"\s+", "", s)


def normalize_host_ot(v: object) -> str:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return ""
    s = strip_accents(str(v)).lower().strip()
    
    # Si contiene una descripción con IP del estilo "10.0.0.1 (Servidor)", extraer solo el nombre
    if "(" in s and ")" in s:
        m_name = re.search(r"\(([^)]+)\)", s)
        if m_name:
            cand = m_name.group(1).strip()
            if not re.match(r"^[\d\.]+$", cand):
                s = cand
                
    # Remover prefijos/sufijos de IP con barras invertidas o normales (ej. "10.0.0.1 \ Servidor" -> "Servidor")
    # Manejamos espacios opcionales alrededor de la barra
    s = re.sub(r"^[0-9\.]+\s*[\\/]\s*", "", s)
    s = re.sub(r"\s*[\\/]\s*[0-9\.]+$", "", s)
    
    # Manejo de FQDN: Si contiene puntos y NO es una IP, tomar solo la primera parte
    if "." in s and not re.match(r"^[\d\.]+$", s):
        s = s.split(".")[0]
    
    # Solo alfanuméricos para normalizar el nombre del host
    s = re.sub(r"[^a-z0-9]", "", s)
    return s


def normalize_ip_or_host(ip_val: object, host_val: object, netbios_val: object) -> str:
    def clean(x: object) -> str:
        if x is None or (isinstance(x, float) and pd.isna(x)):
            return ""
        return str(x).strip().lower()

    # Intento de IP pura (agresivo: buscar patrón de IP dentro de la cadena)
    def extract_ip(s: str) -> Optional[str]:
        # Buscar IPv4
        m4 = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", s)
        if m4: return m4.group(1)
        # Buscar IPv6 simple
        m6 = re.search(r"([0-9a-fA-F:]+:[0-9a-fA-F:]+)", s)
        if m6 and ":" in m6.group(1): return m6.group(1)
        return None

    ip_s = clean(ip_val)
    if ip_s:
        ip_found = extract_ip(ip_s)
        if ip_found: return ip_found
        return clean_host_url(re.sub(r"\s+", "", ip_s))

    host_s = clean(host_val)
    if host_s:
        ip_found = extract_ip(host_s)
        if ip_found: return ip_found
        return clean_host_url(re.sub(r"\s+", "", host_s))

    nb_s = clean(netbios_val)
    if nb_s:
        return re.sub(r"\s+", "", nb_s)

    return ""


def normalize_port(port_val: object) -> str:
    if port_val is None or (isinstance(port_val, float) and pd.isna(port_val)):
        return "N/A"
    
    # Manejar floats explícitos para evitar el ".0" (ej. 80.0 -> "80")
    if isinstance(port_val, float):
        if port_val == 0: return "N/A"
        return str(int(port_val))
        
    s = str(port_val).strip()
    if not s or s.lower() in ["nan", "none", "null", "", "0"]:
        return "N/A"
    
    # Si parece un float en string (ej. "80.0")
    if "." in s:
        try:
            f = float(s)
            if f == 0: return "N/A"
            return str(int(f))
        except:
            pass

    m = re.search(r"(\d+)", s)
    if not m:
        return "N/A"
    
    res = m.group(1)
    return "N/A" if res == "0" else res


def normalize_name(name_val: object) -> str:
    if name_val is None or (isinstance(name_val, float) and pd.isna(name_val)):
        return ""
    # Unescape HTML entities first (e.g. &lt; -> <)
    s = html.unescape(str(name_val))
    s = strip_accents(s).strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s


def normalize_name_ot(name_val: object) -> str:
    if name_val is None or (isinstance(name_val, float) and pd.isna(name_val)):
        return ""
    # Más agresivo para OT: Solo letras, números y espacios
    # Unescape HTML entities first (e.g. &lt; -> <)
    s = html.unescape(str(name_val))
    s = strip_accents(s).lower()
    
    # Mapeo específico para certificados SSL
    if "ssl self signed certificate" in s or "ssl self-signed certificate" in s or "ssl self signed" in s:
        return "ssl certificate cannot be trusted"
        
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def normalize_cve(cve_val: object) -> str:
    if cve_val is None or (isinstance(cve_val, float) and pd.isna(cve_val)):
        return ""
    s = strip_accents(str(cve_val)).strip().upper()
    if not s:
        return ""
    parts = re.split(r"[,\s;]+", s)
    parts = [p.strip() for p in parts if p.strip()]
    return ";".join(sorted(set(parts)))


def normalize_cvss(cvss: Any) -> str:
    try:
        if pd.isna(cvss) or cvss == "":
            return "0.0"
        s = str(cvss).strip().replace(",", ".")
        val = float(s)
        return f"{val:.1f}"
    except (ValueError, TypeError):
        return "0.0"


def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()


def build_key(asset_id: str, port: str, name: str, cve: str, output: str = "") -> str:
    if not (asset_id and (name or cve)):
        return ""
    
    p = normalize_port(port)
    n = str(name).strip().lower()
    c = str(cve).strip().upper()
    o = str(output).strip().lower()
    
    return sha1_hex(f"{asset_id}|{p}|{n}|{c}|{o}")

def build_key_no_cve(asset_id: str, port: str, name: str, output: str = "") -> str:
    if not (asset_id and name):
        return ""
    p = normalize_port(port)
    n = str(name).strip().lower()
    o = str(output).strip().lower()
    return sha1_hex(f"{asset_id}|{p}|{n}|{o}")

def build_key_infra_identity(asset_id: str, port: str, name: str) -> str:
    """Clave de identidad pura para Infra (sin CVE ni Output)."""
    if not (asset_id and name):
        return ""
    p = normalize_port(port)
    n = str(name).strip().lower()
    return sha1_hex(f"{asset_id}|{p}|{n}")

def build_key_ot(ip: str, host: str, port: str, name: str, output: str = "") -> str:
    """Clave literal OT de 4 campos según rúbrica (Nombre, IP, Host, Puerto) + Output opcional."""
    if not name or not ip:
        return ""
    i = normalize_ip_only(ip)
    h = normalize_host_ot(host)
    p = normalize_port(port)
    n = normalize_name_ot(name)
    o = str(output).strip().lower()
    return sha1_hex(f"{i}|{h}|{p}|{n}|{o}")

def build_key_ot_no_output(ip: str, host: str, port: str, name: str) -> str:
    """Clave OT de 4 campos (Nombre, IP, Host, Puerto) sin Output para fallback."""
    if not name or not ip:
        return ""
    i = normalize_ip_only(ip)
    h = normalize_host_ot(host)
    p = normalize_port(port)
    n = normalize_name_ot(name)
    return sha1_hex(f"{i}|{h}|{p}|{n}")


def build_key_ot_identity(ip: str, host: str, name: str) -> str:
    """Clave OT de 3 campos (Nombre, IP, Host) ignorando Puerto para mayor robustez ante variaciones."""
    if not name or not ip:
        return ""
    i = normalize_ip_only(ip)
    h = normalize_host_ot(host)
    n = normalize_name_ot(name)
    return sha1_hex(f"{i}|{h}|{n}")


def build_key_apps(app_name: str, host: str, port: str, vuln_name: str, cve: str, output: str = "") -> str:
    """
    Clave para aplicaciones (incluye host para mayor precisión):
      - app|host|port|cve|output  (si hay cve)
      - app|host|port|name|output (si no)
    """
    if not (app_name and (vuln_name or cve)):
        return ""
    
    h = clean_host_url(host)
    p = normalize_port(port)
    o = str(output).strip().lower()
    base = f"{app_name}|{h}|{p}"
        
    if cve:
        return sha1_hex(f"{base}|{cve}|{o}")
    
    return sha1_hex(f"{base}|{vuln_name}|{o}")

def build_key_apps_identity(app_name: str, host: str, port: str, vuln_name: str, cve: str) -> str:
    """
    Clave de identidad para aplicaciones (sin output).
    """
    if not (app_name and (vuln_name or cve)):
        return ""
    
    h = clean_host_url(host)
    p = normalize_port(port)
    base = f"{app_name}|{h}|{p}"
        
    if cve:
        return sha1_hex(f"{base}|{cve}")
    
    return sha1_hex(f"{base}|{vuln_name}")


# -----------------------------
# Mapeo de columnas
# -----------------------------
NEW_COLS = {
    "risk": ["Risk", "Severity", "Tipo de riesgo", "TipoDeRiesgo"],
    "cvss": ["CVSS", "CVS", "CVSS Score", "CVSSScore"],
    "cve": ["CVE", "CVEs"],
    "host": ["Host", "Hostname", "Host Nombre", "HostNombre", "Host Name", "Host / NETBIOS", "HostNETBIOS"],
    "ip": ["IP Address", "IPAddress", "IP", "Host IP", "HostIP"],
    "netbios": ["NetBios", "NetBios Name", "NetBiosName", "Net Bios", "Host / NETBIOS", "HostNETBIOS"],
    "port": ["Port", "Puerto", "ServicePort"],
    "name": ["Name", "Plugin Name", "PluginName", "Title", "Vulnerabilidad", "VULNERABILIDADES DETECTADAS"],
    "desc": ["Description", "Desc", "Descripcion", "Descripción"],
    "solution": ["Solution", "Fix", "Remediation", "Remediacion", "Remediación"],
    "refs": ["See Also", "SeeAlso", "References", "Referencias", "Referencia"],
    "output": ["Plugin Output", "PluginOutput", "Output"],
}

HIST_COLS = {
    "risk": ["Riesgo", "Tipo de riesgo", "TipoDeRiesgo", "Risk", "Severity"],
    "mitigado": ["Mitigado", "Mitigation", "Mitigated", "Estado", "Status"],
    "cvss": ["CVSS", "CVS", "CVSS Score", "CVSSScore"],
    "cve": ["CVE", "CVEs"],
    "host": ["Host", "Hostname", "Host Nombre", "HostNombre", "Host Name"],
    "ip": ["IP Address", "IPAddress", "IP", "Host IP", "HostIP"],
    "netbios": ["NetBios", "NetBios Name", "NetBiosName", "Net Bios"],
    "port": ["Port", "Puerto", "ServicePort"],
    "name": ["Name", "Plugin Name", "PluginName", "Title", "Vulnerabilidad", "Vulnerabilidad *Producción*", "Vulnerabilidad *Desarrollo*", "VULNERABILIDADES DETECTADAS"],
    "desc": ["Description", "Desc", "Descripcion", "Descripción"],
    "output": ["Output", "Plugin Output", "PluginOutput"],
}

HIST_COLS_OT = {
    "risk": ["Tipo de riesgo", "Riesgo", "Severity"],
    "cvss": ["CVSS", "Riesgo CVSS", "Severity CVSS", "puntuación CVSS"],
    "mitigado": ["Mitigado", "Estado"],
    "modo_escaneo": ["Modo del escaneo", "Modo escaneo", "Tipo de escaneo"],
    "novedad": ["Novedad", "Novedad del hallazgo", "Novedad hallazgo", "Novedad de Hallazgo", "Novedad del Hallazgo"],
    "name": ["Vulnerabilidad", "VULNERABILIDADES DETECTADAS", "Name", "Plugin Name"],
    "port": ["Puerto", "Port"],
    "ip": ["Host IP", "IP Address", "IP"],
    "output": ["Output", "Plugin Output", "PluginOutput"],
    "host": ["Host Nombre", "HostNombre", "Host", "Hostname", "Host / NETBIOS"],
    "netbios": ["NetBios", "NetBios Name", "NetBiosName", "Net Bios"],
    "cve": ["CVE", "CVEs"],
    "desc": ["Description", "Desc", "Descripcion", "Descripción"],
}

HIST_COLS_AD = {
    "risk": ["Riesgo", "Tipo de riesgo", "TipoDeRiesgo", "Risk", "Severity"],
    "mitigado": ["Mitigado", "Mitigation", "Mitigated", "Estado", "Status"],
    "cvss": ["CVSS", "CVS", "CVSS Score", "CVSSScore"],
    "cve": ["CVE", "CVEs"],
    "host": ["Host", "Hostname", "Host Nombre", "HostNombre", "Host Name"],
    "ip": ["IP Address", "IPAddress", "IP", "Host IP", "HostIP"],
    "netbios": ["NetBios", "NetBios Name", "NetBiosName", "Net Bios"],
    "port": ["Port", "Puerto", "ServicePort"],
    "name": ["Vulnerabilidad *Directorio Activo*", "Vulnerabilidad", "VULNERABILIDADES DETECTADAS", "Name"],
    "desc": ["Description", "Desc", "Descripcion", "Descripción"],
    "output": ["Output", "Plugin Output", "PluginOutput"],
}

NEW_COLS_APPS = {
    "cve": ["CVE", "CVEs"],
    "cvss": ["CVSS", "CVS", "CVSS Score", "CVSSScore"],
    "risk": ["Risk", "Severity", "Tipo de riesgo", "TipoDeRiesgo"],
    "host": ["Host", "Hostname"],
    "protocol": ["Protocol", "Proto", "Protocolo"],
    "port": ["Port", "Puerto"],
    "name": ["Name", "Plugin Name", "PluginName", "Vulnerabilidad"],
    "desc": ["Description", "Descripcion", "Descripción"],
    "output": ["Plugin Output", "PluginOutput", "Output"],
    "solution": ["Solution", "Fix", "Remediacion", "Remediación"],
}

HIST_COLS_APPS = {
    "risk": ["Tipo de riesgo", "TipoDeRiesgo", "Risk", "Riesgo", "Severity"],
    "mitigado": ["Mitigado", "Mitigation", "Mitigated", "Estado", "Status"],
    "cve": ["CVE", "CVEs"],
    "cvss": ["CVSS", "CVS", "CVSS Score", "CVSSScore"],
    "area_escaneo": ["Area escaneo", "AreaEscaneo", "Área escaneo"],
    "area_impacto": ["Area Impacto", "AreaImpacto", "Área Impacto"],
    "port": ["Puerto", "Port"],
    "host": ["Host", "Hostname"],
    "app": ["Aplicación", "Aplicacion", "Application", "App"],
    "vuln_detectadas": ["VULNERABILIDADES DETECTADAS"],
    "name": ["Vulnerabilidad", "Name", "Plugin Name", "PluginName", "Vulnerabilidad *Producción*", "Vulnerabilidad *Desarrollo*"],
    "desc": ["Descripción", "Descripcion", "Description"],
    "output": ["Output", "Plugin Output", "PluginOutput"],
    "solution": ["Remediacion", "Remediación", "Solution", "Fix"],
}


def resolve_cols(df: pd.DataFrame, mapping: Dict[str, List[str]]) -> Dict[str, Optional[str]]:
    lookup = build_col_lookup(df)
    return {k: pick_col(lookup, cands) for k, cands in mapping.items()}


def get_series(df: pd.DataFrame, cols: Dict[str, Optional[str]], key: str) -> pd.Series:
    c = cols.get(key)
    if c and c in df.columns:
        return df[c]
    return pd.Series([""] * len(df), index=df.index)


# -----------------------------
# Preparación de datos
# -----------------------------
def prepare_new(df_new: pd.DataFrame, min_risk: str, cols: Dict[str, Optional[str]], tipo: str = "infra") -> pd.DataFrame:
    df_new = df_new.copy()
    df_new["__risk_en"] = get_series(df_new, cols, "risk").apply(normalize_risk_to_en)
    df_new = df_new[df_new["__risk_en"].isin(["medium", "high", "critical"])].copy()
    if not df_new.empty:
        df_new = df_new[df_new["__risk_en"].apply(lambda r: risk_passes_min(r, min_risk))].copy()


    out = pd.DataFrame({
        "Risk_EN": df_new["__risk_en"].fillna(""),
        "Riesgo_ES": df_new["__risk_en"].map(RISK_EN_TO_ES).fillna(""),
        "CVSS": get_series(df_new, cols, "cvss").fillna(""),
        "CVE": get_series(df_new, cols, "cve").fillna(""),
        "Host": get_series(df_new, cols, "host").fillna(""),
        "IP Address": get_series(df_new, cols, "ip").fillna(""),
        "NetBios": get_series(df_new, cols, "netbios").fillna(""),
        "Port": get_series(df_new, cols, "port").apply(normalize_port),
        "Name": get_series(df_new, cols, "name").fillna(""),
        "Description": get_series(df_new, cols, "desc").fillna(""),
        "Solution": get_series(df_new, cols, "solution").fillna(""),
        "See Also": get_series(df_new, cols, "refs").fillna(""),
        "Plugin Output": get_series(df_new, cols, "output").fillna(""),
        "Fuente": "Nuevo",
    })

    out["port_norm"] = out["Port"].apply(normalize_port)
    if tipo == "ot":
        out["name_norm"] = out["Name"].apply(normalize_name_ot)
        out["cve_norm"] = out["CVE"].apply(normalize_cve)
        out["cvss_norm"] = out["CVSS"].apply(normalize_cvss)
        
        # Nuevos OT: Llaves de 4 campos (IP, Host, Puerto, Nombre) + Output
        out["key_hash"] = [build_key_ot(ip, h, p, n, o) for ip, h, p, n, o in zip(out["IP Address"], out["Host"], out["Port"], out["Name"], out["Plugin Output"])]
        out["key_hash_nb"] = [build_key_ot(ip, nb, p, n, o) for ip, nb, p, n, o in zip(out["IP Address"], out["NetBios"], out["Port"], out["Name"], out["Plugin Output"])]
        
        # Fallbacks (sin output)
        out["key_hash_no_out"] = [build_key_ot_no_output(ip, h, p, n) for ip, h, p, n in zip(out["IP Address"], out["Host"], out["Port"], out["Name"])]
        out["key_hash_nb_no_out"] = [build_key_ot_no_output(ip, nb, p, n) for ip, nb, p, n in zip(out["IP Address"], out["NetBios"], out["Port"], out["Name"])]

        # Claves de Identidad (3 campos: IP, Host, Nombre) para manejar variaciones de puerto
        out["key_hash_identity"] = [build_key_ot_identity(ip, h, n) for ip, h, n in zip(out["IP Address"], out["Host"], out["Name"])]
        out["key_hash_nb_identity"] = [build_key_ot_identity(ip, nb, n) for ip, nb, n in zip(out["IP Address"], out["NetBios"], out["Name"])]
    else:
        out["asset_id_norm"] = out.apply(lambda r: normalize_ip_or_host(r["IP Address"], r["Host"], r["NetBios"]), axis=1)
        out["name_norm"] = out["Name"].apply(normalize_name)
        out["cve_norm"] = out["CVE"].apply(normalize_cve)
        out["cvss_norm"] = out["CVSS"].apply(normalize_cvss)
        out["key_hash"] = out.apply(lambda r: build_key(r["asset_id_norm"], r["port_norm"], r["name_norm"], r["cve_norm"], r["Plugin Output"]), axis=1)
        out["key_hash_no_cve"] = out.apply(lambda r: build_key_no_cve(r["asset_id_norm"], r["port_norm"], r["name_norm"], r["Plugin Output"]), axis=1)
        out["key_hash_identity"] = out.apply(lambda r: build_key_infra_identity(r["asset_id_norm"], r["port_norm"], r["name_norm"]), axis=1)
        
        # Llaves de respaldo por IP y por Host individuales para mayor robustez
        out["key_id_ip"] = out.apply(lambda r: build_key_infra_identity(normalize_ip_only(r["IP Address"]), r["port_norm"], r["name_norm"]), axis=1)
        out["key_id_host"] = out.apply(lambda r: build_key_infra_identity(clean_host_url(r["Host"]), r["port_norm"], r["name_norm"]), axis=1)

    return out


def prepare_hist(df_hist: pd.DataFrame, min_risk: str, cols: Dict[str, Optional[str]], tipo: str = "infra") -> pd.DataFrame:
    df_hist = df_hist.copy()
    
    # El filtro por Novedad del hallazgo = 'auto' ya se aplica antes (en compare_vulnerabilities)
    # No se duplica aquí para evitar pérdida de datos.
    
    df_hist["__risk_en"] = get_series(df_hist, cols, "risk").apply(normalize_risk_to_en)
    df_hist = df_hist[df_hist["__risk_en"].isin(["medium", "high", "critical"])].copy()
    if not df_hist.empty:
        df_hist = df_hist[df_hist["__risk_en"].apply(lambda r: risk_passes_min(r, min_risk))].copy()


    mitigado_col = cols.get("mitigado")
    if not mitigado_col:
        raise ValueError("El histórico debe tener columna 'Mitigado' (o equivalente).")

    out = pd.DataFrame({
        "Risk_EN": df_hist["__risk_en"].fillna(""),
        "Riesgo_ES": df_hist["__risk_en"].map(RISK_EN_TO_ES).fillna(""),
        "Mitigado": df_hist[mitigado_col],
        "CVSS": get_series(df_hist, cols, "cvss").fillna(""),
        "CVE": get_series(df_hist, cols, "cve").fillna(""),
        "Host": get_series(df_hist, cols, "host").fillna(""),
        "IP Address": get_series(df_hist, cols, "ip").fillna(""),
        "NetBios": get_series(df_hist, cols, "netbios").fillna(""),
        "Port": get_series(df_hist, cols, "port").apply(normalize_port),
        "Name": get_series(df_hist, cols, "name").fillna(""),
        "Description": df_hist["Descripción"].fillna("") if "Descripción" in df_hist.columns else get_series(df_hist, cols, "desc").fillna(""),
        "Plugin Output": get_series(df_hist, cols, "output").fillna(""),
        "Fuente": "Historico",
    })

    out["is_open"] = out["Mitigado"].apply(lambda v: is_blank_mitigado(v, tipo=tipo))
    out["port_norm"] = out["Port"].apply(normalize_port)
    if tipo == "ot":
        out["name_norm"] = out["Name"].apply(normalize_name_ot)
        out["cve_norm"] = out["CVE"].apply(normalize_cve)
        out["cvss_norm"] = out["CVSS"].apply(normalize_cvss)
        
        # Histórico OT: Llaves de 4 campos + Output
        out["key_hash"] = [build_key_ot(ip, h, p, n, o) for ip, h, p, n, o in zip(out["IP Address"], out["Host"], out["Port"], out["Name"], out["Plugin Output"])]
        out["key_hash_nb"] = [build_key_ot(ip, nb, p, n, o) for ip, nb, p, n, o in zip(out["IP Address"], out["NetBios"], out["Port"], out["Name"], out["Plugin Output"])]

        # Fallbacks (sin output)
        out["key_hash_no_out"] = [build_key_ot_no_output(ip, h, p, n) for ip, h, p, n in zip(out["IP Address"], out["Host"], out["Port"], out["Name"])]
        out["key_hash_nb_no_out"] = [build_key_ot_no_output(ip, nb, p, n) for ip, nb, p, n in zip(out["IP Address"], out["NetBios"], out["Port"], out["Name"])]

        # Claves de Identidad (3 campos: IP, Host, Nombre)
        out["key_hash_identity"] = [build_key_ot_identity(ip, h, n) for ip, h, n in zip(out["IP Address"], out["Host"], out["Name"])]
        out["key_hash_nb_identity"] = [build_key_ot_identity(ip, nb, n) for ip, nb, n in zip(out["IP Address"], out["NetBios"], out["Name"])]
    else:
        out["asset_id_norm"] = out.apply(lambda r: normalize_ip_or_host(r["IP Address"], r["Host"], r["NetBios"]), axis=1)
        out["name_norm"] = out["Name"].apply(normalize_name)
        out["cve_norm"] = out["CVE"].apply(normalize_cve)
        out["cvss_norm"] = out["CVSS"].apply(normalize_cvss)
        out["key_hash"] = out.apply(lambda r: build_key(r["asset_id_norm"], r["port_norm"], r["name_norm"], r["cve_norm"], r["Plugin Output"]), axis=1)
        out["key_hash_no_cve"] = out.apply(lambda r: build_key_no_cve(r["asset_id_norm"], r["port_norm"], r["name_norm"], r["Plugin Output"]), axis=1)
        out["key_hash_identity"] = out.apply(lambda r: build_key_infra_identity(r["asset_id_norm"], r["port_norm"], r["name_norm"]), axis=1)
        
        # Llaves de respaldo por IP y por Host individuales para mayor robustez
        out["key_id_ip"] = out.apply(lambda r: build_key_infra_identity(normalize_ip_only(r["IP Address"]), r["port_norm"], r["name_norm"]), axis=1)
        out["key_id_host"] = out.apply(lambda r: build_key_infra_identity(clean_host_url(r["Host"]), r["port_norm"], r["name_norm"]), axis=1)
    return out


def prepare_new_apps(df_new: pd.DataFrame, min_risk: str, cols: Dict[str, Optional[str]], app_name: str) -> pd.DataFrame:
    df_new = df_new.copy()
    
    risk_col_name = cols.get("risk")
    logger.info(f"[{app_name}] Cols resolution: Risk='{risk_col_name}'. DF Shape: {df_new.shape}")
    
    try:
        raw_risk = get_series(df_new, cols, "risk")
        df_new["__risk_en"] = raw_risk.apply(normalize_risk_to_en)
        logger.debug(f"[{app_name}] __risk_en created. Unique values: {df_new['__risk_en'].unique()}")
    except Exception as e:
        logger.error(f"[{app_name}] Failed to create __risk_en: {e}")
        raise

    df_new = df_new[df_new["__risk_en"].isin(["medium", "high", "critical"])].copy()
    
    if df_new.empty:
        logger.warning(f"[{app_name}] No vulnerabilities match risk filter (medium/high/critical). Returning empty.")
        # Return empty structure with expected columns
        return pd.DataFrame({
            "Aplicación": [], "Risk_EN": [], "Riesgo_ES": [], "CVSS": [], "CVE": [],
            "Host": [], "Protocol": [], "Port": [], "Name": [], "Description": [],
            "Plugin Output": [], "Solution": [], "Fuente": [], "app_norm": [],
            "port_norm": [], "name_norm": [], "cve_norm": [], "key_hash": []
        })

    df_new = df_new[df_new["__risk_en"].apply(lambda r: risk_passes_min(r, min_risk))].copy()

    out = pd.DataFrame({
        "Aplicación": app_name,
        "Risk_EN": df_new["__risk_en"].fillna(""),
        "Riesgo_ES": df_new["__risk_en"].map(RISK_EN_TO_ES).fillna(""),
        "CVSS": get_series(df_new, cols, "cvss").fillna(""),
        "CVE": get_series(df_new, cols, "cve").fillna(""),
        "Host": get_series(df_new, cols, "host").fillna(""),
        "Protocol": get_series(df_new, cols, "protocol").fillna(""),
        "Port": get_series(df_new, cols, "port").apply(normalize_port),
        "Name": get_series(df_new, cols, "name").fillna(""),
        "Description": get_series(df_new, cols, "desc").fillna(""),
        "Plugin Output": get_series(df_new, cols, "output").fillna(""),
        "Solution": get_series(df_new, cols, "solution").fillna(""),
        "Fuente": "Nuevo",
    })

    out["app_norm_robust"] = normalize_app_name(app_name)
    out["host_norm"] = out["Host"].apply(clean_host_url)
    out["port_norm"] = out["Port"].apply(normalize_port)
    out["name_norm"] = out["Name"].apply(normalize_name)
    out["cve_norm"] = out["CVE"].apply(normalize_cve)
    out["output_norm"] = out["Plugin Output"].apply(normalize_output_robust)
    
    out["key_hash"] = out.apply(lambda r: build_key_apps(r["app_norm_robust"], r["Host"], r["port_norm"], r["name_norm"], r["cve_norm"], r["output_norm"]), axis=1)
    out["key_hash_identity"] = out.apply(lambda r: build_key_apps_identity(r["app_norm_robust"], r["Host"], r["port_norm"], r["name_norm"], r["cve_norm"]), axis=1)

    return out


def prepare_hist_apps(df_hist: pd.DataFrame, min_risk: str, cols: Dict[str, Optional[str]], app_name: str) -> pd.DataFrame:
    df_hist = df_hist.copy()

    app_col = cols.get("app")
    if not app_col:
        raise ValueError("El histórico de aplicaciones debe tener columna 'Aplicación' (o equivalente).")

    total_rows = len(df_hist)
    app_name_robust = normalize_app_name(app_name)
    df_hist["__app_robust"] = get_series(df_hist, cols, "app").apply(normalize_app_name)
    df_hist = df_hist[df_hist["__app_robust"] == app_name_robust].copy()
    rows_after_app_filter = len(df_hist)

    logger.info(f"[{app_name}] Histórico: Total={total_rows} -> Filtrado por App Robust='{app_name_robust}'={rows_after_app_filter}")
    
    if rows_after_app_filter == 0:
        print(f"ADVERTENCIA: No se encontraron registros para la aplicación '{app_name}' en el histórico.")

    df_hist["__risk_en"] = get_series(df_hist, cols, "risk").apply(normalize_risk_to_en)
    df_hist = df_hist[df_hist["__risk_en"].isin(["medium", "high", "critical"])].copy()
    rows_after_risk_filter = len(df_hist)
    
    if rows_after_risk_filter == 0:
         logger.warning(f"[{app_name}] Histórico: 0 filas tras filtro de riesgo (medium/high/critical).")

    df_hist = df_hist[df_hist["__risk_en"].apply(lambda r: risk_passes_min(r, min_risk))].copy()
    rows_after_min_risk = len(df_hist)
    
    logger.info(f"[{app_name}] Histórico: RiesgoValido={rows_after_risk_filter} -> MinRisk({min_risk})={rows_after_min_risk}")

    if df_hist.empty:
        # En el histórico puede pasar que no haya registros para esa app con riesgo >= medium
        return pd.DataFrame({
            "Aplicación": [], "Risk_EN": [], "Riesgo_ES": [], "Mitigado": [], "CVSS": [],
            "CVE": [], "Area escaneo": [], "Area Impacto": [], "Host": [], "Port": [],
            "VULNERABILIDADES DETECTADAS": [], "Name": [], "Description": [],
            "Output": [], "Solution": [], "Fuente": [], "is_open": [], "app_norm": [],
            "port_norm": [], "name_norm": [], "cve_norm": [], "key_hash": []
        })

    df_hist = df_hist[df_hist["__risk_en"].apply(lambda r: risk_passes_min(r, min_risk))].copy()

    mitigado_col = cols.get("mitigado")
    if not mitigado_col:
        raise ValueError("El histórico debe tener columna 'Mitigado' (o equivalente).")

    # Debug logs for mitigation status
    unique_vals = df_hist[mitigado_col].dropna().unique()
    nan_count = df_hist[mitigado_col].isna().sum()
    logger.info(f"[{app_name}] Columna Mitigado: '{mitigado_col}'. Valores únicos: {unique_vals[:5]}. NaNs: {nan_count}")
    
    # Sort by mitigado column to ensure non-null values come last (for deduplication)
    # na_position='first' puts NaNs at the top. keep='last' will pick the bottom (non-NaN).
    df_hist = df_hist.sort_values(by=mitigado_col, na_position='first').copy()

    out = pd.DataFrame({
        "Aplicación": get_series(df_hist, cols, "app").fillna(""),
        "Risk_EN": df_hist["__risk_en"].fillna(""),
        "Riesgo_ES": df_hist["__risk_en"].map(RISK_EN_TO_ES).fillna(""),
        "Mitigado": df_hist[mitigado_col],
        "CVSS": get_series(df_hist, cols, "cvss").fillna(""),
        "CVE": get_series(df_hist, cols, "cve").fillna(""),
        "Area escaneo": get_series(df_hist, cols, "area_escaneo").fillna(""),
        "Area Impacto": get_series(df_hist, cols, "area_impacto").fillna(""),
        "Host": get_series(df_hist, cols, "host").fillna(""),
        "Port": get_series(df_hist, cols, "port").apply(normalize_port),
        "VULNERABILIDADES DETECTADAS": get_series(df_hist, cols, "vuln_detectadas").fillna(""),
        "Name": get_series(df_hist, cols, "name").fillna(""),
        "Description": get_series(df_hist, cols, "desc").fillna(""),
        "Plugin Output": get_series(df_hist, cols, "output").fillna(""),
        "Solution": get_series(df_hist, cols, "solution").fillna(""),
        "Fuente": "Historico",
    })

    out["is_open"] = out["Mitigado"].apply(is_blank_mitigado)
    out["app_norm_robust"] = app_name_robust
    out["host_norm"] = out["Host"].apply(clean_host_url)
    out["port_norm"] = out["Port"].apply(normalize_port)
    out["name_norm"] = out["Name"].apply(normalize_name)
    out["cve_norm"] = out["CVE"].apply(normalize_cve)
    out["output_norm"] = out["Plugin Output"].apply(normalize_output_robust)
    
    out["key_hash"] = out.apply(lambda r: build_key_apps(r["app_norm_robust"], r["Host"], r["port_norm"], r["name_norm"], r["cve_norm"], r["output_norm"]), axis=1)
    out["key_hash_identity"] = out.apply(lambda r: build_key_apps_identity(r["app_norm_robust"], r["Host"], r["port_norm"], r["name_norm"], r["cve_norm"]), axis=1)
    
    # Debug: Log duplicates before dedupe
    rows_before_dedupe = len(out)
    unique_keys = out["key_hash"].nunique()
    logger.info(f"[{app_name}] Histórico: Antes Dedupe={rows_before_dedupe}. Keys Únicas={unique_keys}. Duplicados latentes={rows_before_dedupe - unique_keys}")
        
    return out


# -----------------------------
# Unificación de CSVs por aplicación
# -----------------------------
# Lista de aplicaciones soportadas
APLICACIONES_SOPORTADAS = [
    "Acuagis",
    "Acuaprocess",
    "Documento Equivalente",
    "Web Acuacar",
    "Acuaprocess Desarrollo",
]


def merge_app_csvs(app_files: Dict[str, bytes]) -> io.BytesIO:
    """
    Unifica múltiples CSVs de aplicaciones en un solo archivo.
    REALIZA ESTANDARIZACIÓN PREVIA de columnas para asegurar consistencia.
    """
    if not app_files:
        raise ValueError("Debe proporcionar al menos un archivo CSV.")
    
    dataframes = []
    
    for app_name, csv_content in app_files.items():
        if not csv_content:
            continue
            
        try:
            logger.info(f"[{app_name}] Estandarizando CSV...")
            df = read_csv_from_bytes(csv_content)
            df = drop_header_like_rows(df)
            
            # Resolver columnas locales para este archivo
            cols = resolve_cols(df, NEW_COLS_APPS)
            
            # Verificar columnas mínimas críticas
            if not cols.get("risk"): 
                logger.warning(f"[{app_name}] No se encontró columna de Riesgo. Columnas disponibles: {df.columns.tolist()}")
            
            # Crear DataFrame estandarizado
            std_df = pd.DataFrame()
            std_df["Aplicación"] = [app_name] * len(df)
            
            # Normalizar Riesgo para filtrado
            risk_series = get_series(df, cols, "risk")
            risk_en = risk_series.apply(normalize_risk_to_en)
            
            # Filtrar por riesgo (medium, high, critical)
            mask = risk_en.isin(["medium", "high", "critical"])
            df_filtered = df[mask].copy()
            risk_en_filtered = risk_en[mask]
            
            if len(df_filtered) == 0:
                logger.warning(f"[{app_name}] No se encontraron vulnerabilidades con riesgo Medium, High o Critical. Saltando.")
                continue

            # Crear DataFrame estandarizado
            # Usar .reset_index(drop=True) para evitar problemas de alineación
            std_df = pd.DataFrame()
            std_df["Aplicación"] = [app_name] * len(df_filtered)
            std_df["Risk"] = risk_en_filtered.reset_index(drop=True).fillna("")
            std_df["Riesgo_ES"] = risk_en_filtered.map(RISK_EN_TO_ES).reset_index(drop=True).fillna("")
            std_df["Name"] = get_series(df_filtered, cols, "name").reset_index(drop=True).fillna("")
            std_df["Description"] = get_series(df_filtered, cols, "desc").reset_index(drop=True).fillna("")
            std_df["Solution"] = get_series(df_filtered, cols, "solution").reset_index(drop=True).fillna("")
            std_df["Plugin Output"] = get_series(df_filtered, cols, "output").reset_index(drop=True).fillna("")
            std_df["CVSS"] = get_series(df_filtered, cols, "cvss").reset_index(drop=True).fillna("")
            std_df["CVE"] = get_series(df_filtered, cols, "cve").reset_index(drop=True).fillna("")
            std_df["Host"] = get_series(df_filtered, cols, "host").reset_index(drop=True).fillna("")
            std_df["Protocol"] = get_series(df_filtered, cols, "protocol").reset_index(drop=True).fillna("")
            std_df["Port"] = get_series(df_filtered, cols, "port").apply(normalize_port).reset_index(drop=True)
            
            logger.info(f"[{app_name}] Estandarizado y filtrado. Filas: {len(std_df)}")
            dataframes.append(std_df)
            
        except Exception as e:
            logger.error(f"Error procesando {app_name}: {e}")
            raise ValueError(f"Error al procesar CSV de '{app_name}': {e}")
    
    if not dataframes:
        raise ValueError("No se pudieron procesar los archivos CSV proporcionados.")
    
    # Unificar todos los DataFrames
    merged_df = pd.concat(dataframes, ignore_index=True)
    
    # Exportar a CSV en memoria
    output = io.BytesIO()
    # Usar encoding utf-8-sig para compatibilidad con Excel
    merged_df.to_csv(output, index=False, encoding="utf-8-sig")
    output.seek(0)
    
    return output


def compare_all_apps(
    merged_csv_content: bytes,
    historico_content: bytes,
    historico_filename: str,
    min_risk: str = "medium",
    sheet: Optional[str] = None,
) -> Tuple[io.BytesIO, Dict]:
    """
    Compara todas las aplicaciones del CSV unificado contra el histórico.
    Genera un Excel con resultados consolidados y por aplicación.
    
    Args:
        merged_csv_content: CSV unificado con columna 'Aplicación'
        historico_content: Archivo histórico
        historico_filename: Nombre del archivo histórico
        min_risk: Nivel mínimo de riesgo
        sheet: Hoja del Excel histórico (opcional)
    
    Returns:
        BytesIO con el Excel de resultados.
    """
    min_risk = min_risk.strip().lower()
    if min_risk not in RISK_ORDER:
        raise ValueError("min_risk debe ser: medium, high o critical")
    
    # Leer archivos
    df_new_raw = read_csv_from_bytes(merged_csv_content)
    df_hist_raw = read_table_from_bytes(historico_content, historico_filename, sheet)
    
    df_new_raw = drop_header_like_rows(df_new_raw)
    df_hist_raw = drop_header_like_rows(df_hist_raw)
    
    # Verificar que el CSV tiene columna Aplicación
    new_lookup = build_col_lookup(df_new_raw)
    app_col_new = pick_col(new_lookup, ["Aplicación", "Aplicacion", "Application", "App"])
    if not app_col_new:
        raise ValueError("El CSV unificado debe tener columna 'Aplicación'.")
    
    # Obtener lista de aplicaciones únicas
    apps_in_csv = df_new_raw[app_col_new].dropna().unique().tolist()
    
    # Resolver columnas del histórico
    hist_cols = resolve_cols(df_hist_raw, HIST_COLS_APPS)
    if not hist_cols.get("mitigado") or not hist_cols.get("name") or not hist_cols.get("app"):
        raise ValueError("El histórico debe tener 'Mitigado', 'Aplicación' y 'Vulnerabilidad'.")
    
    # 1. Preparar conjuntos totales
    list_nuevo = []
    list_hist = []
    
    for app_name in apps_in_csv:
        df_app = df_new_raw[df_new_raw[app_col_new] == app_name].copy()
        new_cols_local = resolve_cols(df_app, NEW_COLS_APPS)
        if not new_cols_local.get("risk") or not new_cols_local.get("name"):
            continue
            
        nuevo_app = prepare_new_apps(df_app, min_risk, new_cols_local, app_name)
        hist_app = prepare_hist_apps(df_hist_raw, min_risk, hist_cols, app_name)
        
        if not nuevo_app.empty: list_nuevo.append(nuevo_app)
        if not hist_app.empty: list_hist.append(hist_app)
        
    df_nuevo_total = pd.concat(list_nuevo, ignore_index=True) if list_nuevo else pd.DataFrame()
    df_hist_total = pd.concat(list_hist, ignore_index=True) if list_hist else pd.DataFrame()
    
    # Diagnóstico
    nuevo_no_key = df_nuevo_total[df_nuevo_total["key_hash"].astype(str) == ""].copy() if not df_nuevo_total.empty else pd.DataFrame()
    hist_no_key = df_hist_total[df_hist_total["key_hash"].astype(str) == ""].copy() if not df_hist_total.empty else pd.DataFrame()

    # 2. Respetar conteo (Sin deduplicación según requerimiento)
    nuevo_k = df_nuevo_total
    hist_k = df_hist_total
    
    # 3. Conjuntos y Clasificación (Igual que compare_vulnerabilities)
    hist_open = hist_k[hist_k["is_open"] == True].copy() if not hist_k.empty else pd.DataFrame()
    hist_mitig = hist_k[hist_k["is_open"] == False].copy() if not hist_k.empty else pd.DataFrame()
    
    # identity -> robust output mapping for comparison
    hist_open_id_map = {str(r.get("key_hash_identity", "")): str(r.get("output_norm", "")) for _, r in hist_open.iterrows() if str(r.get("key_hash_identity", ""))}
    # identity -> raw output mapping for reporting
    hist_open_raw_map = {str(r.get("key_hash_identity", "")): str(r.get("Plugin Output", "")) for _, r in hist_open.iterrows() if str(r.get("key_hash_identity", ""))}
    
    hist_mitig_id_map = {str(r.get("key_hash_identity", "")): str(r.get("output_norm", "")) for _, r in hist_mitig.iterrows() if str(r.get("key_hash_identity", ""))}

    set_open = set(hist_open["key_hash"].astype(str).tolist())
    set_open_id = set(hist_open_id_map.keys())
    
    # Excluir de mitigados todo lo que ya está como abierto (prioridad abierto)
    hist_mitig = hist_mitig[~hist_mitig["key_hash"].astype(str).isin(set_open)].copy() if not hist_mitig.empty else pd.DataFrame()
    hist_mitig = hist_mitig[~hist_mitig["key_hash_identity"].astype(str).isin(set_open_id)].copy() if not hist_mitig.empty else pd.DataFrame()
    
    set_mitig = set(hist_mitig["key_hash"].astype(str).tolist())
    set_mitig_id = set(hist_mitig_id_map.keys())
    
    set_all_hist = set_open | set_mitig
    set_new = set(nuevo_k["key_hash"].astype(str).tolist()) if not nuevo_k.empty else set()
    set_new_id = set(nuevo_k["key_hash_identity"].astype(str).tolist()) if not nuevo_k.empty else set()
    
    def classify_row_apps(row):
        k = str(row["key_hash"])
        k_id = str(row["key_hash_identity"])
        current_out_norm = str(row.get("output_norm", ""))
        
        # 1. Persistente: Coincidencia exacta (incluye robust output) en Abiertos
        if k in set_open:
            return "P", ""
            
        # 2. Actualizada: Coincidencia de identidad en Abiertos, pero con diferente output robusto
        if k_id in hist_open_id_map:
            old_out_norm = hist_open_id_map[k_id]
            if old_out_norm != current_out_norm:
                return "A", hist_open_raw_map.get(k_id, "")
            else:
                # Si falló 'k in set_open' pero el output robusto es igual, es P
                return "P", ""

        # 3. Reabierta: Coincidencia exacta (incluye robust output) en Mitigados
        if k in set_mitig:
            return "R", ""
            
        # 4. Nueva: Si coincide identidad en Mitigados pero el output es DIFERENTE -> N (según regla user)
        if k_id in hist_mitig_id_map:
            # Si llegamos aquí es porque 'k in set_mitig' falló (output diferente)
            return "N", ""

        return "N", ""
    
    if not nuevo_k.empty:
        res = nuevo_k.apply(classify_row_apps, axis=1)
        nuevo_k["__class"] = [r[0] for r in res]
        nuevo_k["Old_Output"] = [r[1] for r in res]
        
        persistentes = nuevo_k[nuevo_k["__class"] == "P"].copy()
        actualizadas = nuevo_k[nuevo_k["__class"] == "A"].copy()
        reabiertas = nuevo_k[nuevo_k["__class"] == "R"].copy()
        nuevas = nuevo_k[nuevo_k["__class"] == "N"].copy()
    else:
        persistentes = pd.DataFrame()
        actualizadas = pd.DataFrame()
        reabiertas = pd.DataFrame()
        nuevas = pd.DataFrame()
        
    mask_in_new = hist_open["key_hash"].astype(str).isin(set_new) | hist_open["key_hash_identity"].astype(str).isin(set_new_id)
    mitigadas_desde_ultimo = hist_open[~mask_in_new].copy() if not hist_open.empty else pd.DataFrame()
    
    mask_mitig_in_new = hist_mitig["key_hash"].astype(str).isin(set_new) | hist_mitig["key_hash_identity"].astype(str).isin(set_new_id)
    mitigadas_ausentes = hist_mitig[~mask_mitig_in_new].copy() if not hist_mitig.empty else pd.DataFrame()
    
    # 4. Resumen por aplicación
    resumen_por_app = []
    for app_name in apps_in_csv:
        n_count = nuevas[nuevas["Aplicación"] == app_name] if not nuevas.empty else pd.DataFrame()
        p_count = persistentes[persistentes["Aplicación"] == app_name] if not persistentes.empty else pd.DataFrame()
        r_count = reabiertas[reabiertas["Aplicación"] == app_name] if not reabiertas.empty else pd.DataFrame()
        a_up_count = actualizadas[actualizadas["Aplicación"] == app_name] if not actualizadas.empty else pd.DataFrame()
        m_count = mitigadas_desde_ultimo[mitigadas_desde_ultimo["Aplicación"] == app_name] if not mitigadas_desde_ultimo.empty else pd.DataFrame()
        a_count = mitigadas_ausentes[mitigadas_ausentes["Aplicación"] == app_name] if not mitigadas_ausentes.empty else pd.DataFrame()
        
        app_total = nuevo_k[nuevo_k["Aplicación"] == app_name] if not nuevo_k.empty else pd.DataFrame()
        app_hist = hist_k[hist_k["Aplicación"] == app_name] if not hist_k.empty else pd.DataFrame()
        
        risk_counts = n_count["Riesgo_ES"].value_counts(dropna=False).to_dict() if not n_count.empty else {}
        
        resumen_por_app.append({
            "Aplicación": app_name,
            "Total escaneo": len(app_total),
            "Total histórico": len(app_hist),
            "Nuevas": len(n_count),
            "Persistentes": len(p_count),
            "Reabiertas": len(r_count),
            "Actualizadas": len(a_up_count),
            "Mitigadas desde último escaneo": len(m_count),
            "Mitigadas ausentes": len(a_count),
            "Nuevas (crítico)": int(risk_counts.get("critico", 0)),
            "Nuevas (alto)": int(risk_counts.get("alto", 0)),
            "Nuevas (medio)": int(risk_counts.get("medio", 0)),
        })
    df_resumen_apps = pd.DataFrame(resumen_por_app)
    
    # 5. Resumen General (Mismos campos que standard 'Resumen')
    resumen_rows = [
        ("Tipo de análisis", "Aplicaciones (consolidado)"),
        ("Min risk aplicado", min_risk),
        ("Aplicaciones procesadas", len(apps_in_csv)),
        ("Total NUEVO (post filtro)", len(df_nuevo_total)),
        ("Total NUEVO deduplicado", len(nuevo_k)),
        ("Total HISTÓRICO (post filtro)", len(df_hist_total)),
        ("Total HISTÓRICO deduplicado", len(hist_k)),
        ("Nuevas", len(nuevas)),
        ("Persistentes", len(persistentes)),
        ("Actualizadas", len(actualizadas)),
        ("Reabiertas", len(reabiertas)),
        ("Mitigadas desde último escaneo", len(mitigadas_desde_ultimo)),
        ("Mitigadas ausentes en último escaneo", len(mitigadas_ausentes)),
        ("Filas NUEVO sin clave", len(nuevo_no_key)),
        ("Filas HIST sin clave", len(hist_no_key)),
    ]
    risk_counts_total = nuevas["Riesgo_ES"].value_counts(dropna=False).to_dict() if not nuevas.empty else {}
    for k in ["critico", "alto", "medio"]:
        resumen_rows.append((f"Nuevas ({k})", int(risk_counts_total.get(k, 0))))
        
    df_resumen_general = pd.DataFrame(resumen_rows, columns=["Métrica", "Valor"])
    
    # Preparar el JSON summary
    detalles = []
    
    def _add_to_details_apps(df_source, status_label):
        if df_source.empty: return
        for _, row in df_source.iterrows():
            if len(detalles) >= 500: break
            detalles.append({
                "app_name": str(row.get("Aplicación", "")),
                "name": str(row.get("Name", "")),
                "host": str(row.get("Host", "")),
                "ip": str(row.get("IP Address", "")),
                "port": str(row.get("Port", "")),
                "description": str(row.get("Description", "")),
                "plugin_output": str(row.get("Plugin Output", "")),
                "old_output": str(row.get("Old_Output", "")),
                "risk": str(row.get("Riesgo_ES", "")),
                "status": status_label,
            })
            
    _add_to_details_apps(nuevas, "Nuevas")
    _add_to_details_apps(persistentes, "Persistentes")
    _add_to_details_apps(actualizadas, "Actualizadas")
    _add_to_details_apps(reabiertas, "Reabiertas")
    _add_to_details_apps(mitigadas_desde_ultimo, "Mitigadas")

    # The user specifies that the risk detections chart for Apps should reflect the new scan (nuevo_k)
    risk_counts_all = nuevo_k["Riesgo_ES"].value_counts(dropna=False).to_dict() if not nuevo_k.empty else {}

    summary = {
        "tipo": "todas_apps",
        "min_risk": min_risk,
        "total_nuevo": int(len(df_nuevo_total)),
        "total_nuevo_dedup": int(len(nuevo_k)),
        "total_historico": int(len(df_hist_total)),
        "total_historico_dedup": int(len(hist_k)),
        "nuevas": int(len(nuevas)),
        "persistentes": int(len(persistentes)),
        "actualizadas": int(len(actualizadas)),
        "reabiertas": int(len(reabiertas)),
        "mitigadas_desde_ultimo": int(len(mitigadas_desde_ultimo)),
        "mitigadas_ausentes": int(len(mitigadas_ausentes)),
        "detecciones_criticas": int(risk_counts_all.get("critico", 0)),
        "detecciones_altas": int(risk_counts_all.get("alto", 0)),
        "detecciones_medias": int(risk_counts_all.get("medio", 0)),
        "detalles": detalles
    }

    # 6. Generar Excel
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        nuevas.to_excel(writer, sheet_name="Nuevas", index=False)
        actualizadas.to_excel(writer, sheet_name="Actualizadas", index=False)
        mitigadas_desde_ultimo.to_excel(writer, sheet_name="Mitigadas desde último escaneo", index=False)
        reabiertas.to_excel(writer, sheet_name="Reabiertas", index=False)
        persistentes.to_excel(writer, sheet_name="Persistentes", index=False)
        mitigadas_ausentes.to_excel(writer, sheet_name="Mitigadas ausentes en último escaneo", index=False)
        df_resumen_apps.to_excel(writer, sheet_name="Resumen por app", index=False)
        df_resumen_general.to_excel(writer, sheet_name="Resumen general", index=False)
        
        if len(nuevo_no_key) > 0:
            nuevo_no_key.to_excel(writer, sheet_name="Diag_Nuevo_Sin_Key", index=False)
        if len(hist_no_key) > 0:
            hist_no_key.to_excel(writer, sheet_name="Diag_Hist_Sin_Key", index=False)
            
    output.seek(0)
    return output, summary


def dedupe_by_key(df: pd.DataFrame, tipo: str = "infra") -> pd.DataFrame:
    if "key_hash" not in df.columns:
        return df
    
    # Priorizar registros ABIERTOS: ordenar para que True (1) quede al final
    if "is_open" in df.columns:
        df = df.sort_values(by="is_open", ascending=True)

    # El usuario espera que se mantengan detecciones en distintos puertos. Deduplicamos por 4 campos (Identity + Port).
    if tipo == "ot":
        # En OT no usamos Plugin Output para deduplicar, pero sí el Puerto para no perder hallazgos distintos
        if "key_hash_no_out" in df.columns:
            return df[df["key_hash_no_out"].astype(str) != ""].drop_duplicates(subset=["key_hash_no_out"], keep="last").copy()
            
    return df[df["key_hash"].astype(str) != ""].drop_duplicates(subset=["key_hash"], keep="last").copy()


# -----------------------------
# Función principal de comparación
# -----------------------------
def compare_vulnerabilities(
    nuevo_content: bytes,
    nuevo_filename: str,
    historico_content: bytes,
    historico_filename: str,
    min_risk: str = "medium",
    tipo: str = "infra",
    sheet: Optional[str] = None,
) -> Tuple[io.BytesIO, Dict]:
    """
    Compara vulnerabilidades y retorna un Excel en memoria.
    
    Returns:
        BytesIO con el archivo Excel generado.
    """
    min_risk = min_risk.strip().lower()
    if min_risk not in RISK_ORDER:
        raise ValueError("min_risk debe ser: medium, high o critical")

    tipo = tipo.lower().strip()


    # Leer archivos desde bytes
    df_new_raw = read_csv_from_bytes(nuevo_content)
    df_hist_raw = read_table_from_bytes(historico_content, historico_filename, sheet)

    df_new_raw = drop_header_like_rows(df_new_raw)
    df_hist_raw = drop_header_like_rows(df_hist_raw)

    with open("/tmp/match_debug.log", "a") as f_log:
        f_log.write(f"\n--- HISTORICAL FILE INFO ---\n")
        f_log.write(f"Raw rows: {len(df_hist_raw)}\n")
        f_log.write(f"Columns: {list(df_hist_raw.columns)}\n")

    # Seleccionar mapeo y funciones según tipo
    new_cols = resolve_cols(df_new_raw, NEW_COLS)
    
    # Auto-detección de tipo (OT vs Infra)
    if tipo == "infra" and any(c in df_hist_raw.columns for c in ["Modo del escaneo", "Modo del Escaneo"]):
        logger.info(f"[{request_id}] AUTO-DETECT: Archivo tipo OT detectado. Cambiando tipo='infra' -> 'ot'")
        tipo = "ot"

    if tipo == "ot":
        hist_cols = resolve_cols(df_hist_raw, HIST_COLS_OT)
        
        # Filtro OT: Modo del escaneo debe ser 'auto'
        # Esto asegura que solo las vulnerabilidades detectadas automáticamente se tomen en cuenta para la comparación.
        modo_col = hist_cols.get("modo_escaneo")
        if modo_col:
            mask_auto = df_hist_raw[modo_col].astype(str).str.strip().str.lower() == "auto"
            df_hist_raw = df_hist_raw[mask_auto].copy()
            logger.info(f"Hist OT tras filtro modo_escaneo='auto': {len(df_hist_raw)} filas")
        
        # El filtro por riesgo se aplicará dentro de prepare_hist
    elif tipo == "ad":
        hist_cols = resolve_cols(df_hist_raw, HIST_COLS_AD)
    else:
        hist_cols = resolve_cols(df_hist_raw, HIST_COLS)

    if not new_cols.get("risk") or not new_cols.get("name"):
        raise ValueError("El archivo nuevo debe tener columnas de riesgo (Risk) y nombre (Name).")
    if not hist_cols.get("mitigado") or not hist_cols.get("name"):
        raise ValueError("El histórico debe tener 'Mitigado' y nombre (Name/Vulnerabilidad).")

    nuevo = prepare_new(df_new_raw, min_risk, new_cols, tipo=tipo)
    hist = prepare_hist(df_hist_raw, min_risk, hist_cols, tipo=tipo)

    with open("/tmp/match_debug.log", "a") as f_log:
        f_log.write(f"Post-prepare rows: Nuevo={len(nuevo)}, Historico={len(hist)}\n")
        f_log.write(f"Historico Abiertas: {len(hist[hist['is_open'] == True])}\n")
        f_log.write(f"Historico Mitigadas: {len(hist[hist['is_open'] == False])}\n")

    # La lógica de 'Abierto' ya se aplicó en prepare_hist(tipo=tipo)
    
    # Diagnóstico
    nuevo_no_key = nuevo[nuevo["key_hash"].astype(str) == ""].copy()
    hist_no_key = hist[hist["key_hash"].astype(str) == ""].copy()

    # Dedupe (Habilitado para OT para consolidar los 175 registros en los 154 finales)
    if tipo == "ot":
        nuevo_k = dedupe_by_key(nuevo, tipo=tipo)
        # Historial: NO deduplicar para mantener los 154 abiertos exactos del usuario
        hist_k = hist
    else:
        nuevo_k = dedupe_by_key(nuevo)
        hist_k = dedupe_by_key(hist)

    with open("/tmp/match_debug.log", "a") as f_log:
        f_log.write(f"Post-dedupe rows: Nuevo={len(nuevo_k)}, Historico={len(hist_k)}\n")

    # Conjuntos
    hist_open = hist_k[hist_k["is_open"] == True].copy()
    hist_mitig = hist_k[hist_k["is_open"] == False].copy()

    set_open = set(hist_open["key_hash"].astype(str).tolist())
    
    # Priority for open vulnerabilities: remove any mitigated that has the same key as an open one
    hist_mitig = hist_mitig[~hist_mitig["key_hash"].astype(str).isin(set_open)].copy()

    set_mitig = set(hist_mitig["key_hash"].astype(str).tolist())
    set_all_hist = set_open | set_mitig
    set_new = set(nuevo_k["key_hash"].astype(str).tolist())

    # Loguear las llaves que tenemos en el historial abierto para srvwebapp2/10.3.11.26
    hist_matches = hist_open[hist_open["IP Address"].astype(str).str.contains("10.3.11.26", na=False) | 
                             hist_open["Host"].astype(str).str.contains("srvwebapp2", case=False, na=False)]
    
    with open("/tmp/match_debug.log", "a") as f_log:
        f_log.write(f"\n--- DEBUG comparison (tipo={tipo}, min_risk={min_risk}, date={datetime.now()}) ---\n")
        f_log.write(f"hist_cols resolved: {hist_cols}\n")
        f_log.write(f"new_cols resolved: {new_cols}\n")
        f_log.write(f"hist_open length: {len(hist_open)}, hist_mitig length: {len(hist_mitig)}\n")
        if not hist_matches.empty:
            f_log.write(f"--- HIST OPEN ENTRIES (srvwebapp2 / 10.3.11.26) ---\n")
            for _, hr in hist_matches.iterrows():
                f_log.write(f"[HIST] Name='{hr.get('Name')}' | Host='{hr.get('Host')}' | IP='{hr.get('IP Address')}' | Port='{hr.get('Port')}' | CVE='{hr.get('CVE')}'\n")
                f_log.write(f"       Key='{hr.get('key_hash')}'\n")
        else:
            f_log.write(f"No matching entries found in hist_open for IP 10.3.11.26 or host srvwebapp2\n")

    if tipo == "ot":
        # Mapeo de identidad -> output para detectar "Actualizada" y mostrar diferencia
        hist_open_id_map = {}
        for _, r in hist_open.iterrows():
            k_id = str(r.get("key_hash_no_out", ""))
            k_nb_id = str(r.get("key_hash_nb_no_out", ""))
            k_ident = str(r.get("key_hash_identity", ""))
            k_nb_ident = str(r.get("key_hash_nb_identity", ""))
            out_val = str(r.get("Plugin Output", ""))
            if k_id: hist_open_id_map[k_id] = out_val
            if k_nb_id: hist_open_id_map[k_nb_id] = out_val
            if k_ident: hist_open_id_map[k_ident] = out_val
            if k_nb_ident: hist_open_id_map[k_nb_ident] = out_val

        set_hist_open_full = set(hist_open["key_hash"].dropna().astype(str)) | set(hist_open["key_hash_nb"].dropna().astype(str))
        set_hist_open_id = set(hist_open_id_map.keys())

        # Filtrar hist_mitig más profundamente para OT
        mask_mitig_overlap = (
            hist_mitig["key_hash"].astype(str).isin(set_hist_open_full) | 
            hist_mitig["key_hash_nb"].astype(str).isin(set_hist_open_full) |
            hist_mitig["key_hash_no_out"].astype(str).isin(set_hist_open_id) |
            hist_mitig["key_hash_nb_no_out"].astype(str).isin(set_hist_open_id) |
            hist_mitig["key_hash_identity"].astype(str).isin(set_hist_open_id) |
            hist_mitig["key_hash_nb_identity"].astype(str).isin(set_hist_open_id)
        )
        hist_mitig = hist_mitig[~mask_mitig_overlap].copy()
        
        set_hist_mitig_full = (
            set(hist_mitig["key_hash"].dropna().astype(str)) | 
            set(hist_mitig["key_hash_nb"].dropna().astype(str))
        )
        set_hist_mitig_id = (
            set(hist_mitig["key_hash_no_out"].dropna().astype(str)) | 
            set(hist_mitig["key_hash_nb_no_out"].dropna().astype(str)) |
            set(hist_mitig["key_hash_identity"].dropna().astype(str)) |
            set(hist_mitig["key_hash_nb_identity"].dropna().astype(str))
        )

        def classify_row_ot(row):
            k = str(row["key_hash"])
            k_nb = str(row["key_hash_nb"])
            k_id = str(row["key_hash_no_out"])
            k_nb_id = str(row["key_hash_nb_no_out"])
            k_id_pure = str(row["key_hash_identity"])
            k_nb_id_pure = str(row["key_hash_nb_identity"])
            
            # 1. Persistente: Coincidencia en Abiertos (cualquiera de las llaves: 5, 4 o 3 campos)
            if (k in set_hist_open_full or k_nb in set_hist_open_full or 
                k_id in set_hist_open_id or k_nb_id in set_hist_open_id or
                k_id_pure in set_hist_open_id or k_nb_id_pure in set_hist_open_id):
                return "P", ""
            
            # 2. Reabierta: Coincidencia con mitigada
            if (k in set_hist_mitig_full or k_nb in set_hist_mitig_full or 
                k_id in set_hist_mitig_id or k_nb_id in set_hist_mitig_id or
                k_id_pure in set_hist_mitig_id or k_nb_id_pure in set_hist_mitig_id):
                return "R", ""
            
            # 3. Nueva
            return "N", ""
            
        res = nuevo_k.apply(classify_row_ot, axis=1)
        nuevo_k["__class"] = [r[0] for r in res]
        nuevo_k["Old_Output"] = [r[1] for r in res]
        
        persistentes = nuevo_k[nuevo_k["__class"] == "P"].copy()
        actualizadas = nuevo_k[nuevo_k["__class"] == "A"].copy()
        reabiertas = nuevo_k[nuevo_k["__class"] == "R"].copy()
        nuevas = nuevo_k[nuevo_k["__class"] == "N"].copy()
        
        set_new_scan_keys = (
            set(nuevo_k["key_hash"].dropna().astype(str)) | 
            set(nuevo_k["key_hash_nb"].dropna().astype(str)) |
            set(nuevo_k["key_hash_no_out"].dropna().astype(str)) |
            set(nuevo_k["key_hash_nb_no_out"].dropna().astype(str)) |
            set(nuevo_k["key_hash_identity"].dropna().astype(str)) |
            set(nuevo_k["key_hash_nb_identity"].dropna().astype(str))
        )
        
        # 4. Mitigada: En histórico abierto pero NO en el nuevo escaneo
        mask_in_new = (
            hist_open["key_hash"].astype(str).isin(set_new_scan_keys) | 
            hist_open["key_hash_nb"].astype(str).isin(set_new_scan_keys) |
            hist_open["key_hash_no_out"].astype(str).isin(set_new_scan_keys) |
            hist_open["key_hash_nb_no_out"].astype(str).isin(set_new_scan_keys) |
            hist_open["key_hash_identity"].astype(str).isin(set_new_scan_keys) |
            hist_open["key_hash_nb_identity"].astype(str).isin(set_new_scan_keys)
        )
        mitigadas_desde_ultimo = hist_open[~mask_in_new].copy()

        # Nota final para cumplimiento de requerimiento:
        # "Si en el histórico aparece como 'Mitigada', y no aparece en el nuevo escaneo, entonces no es necesario mostrar la vuln"
        # Esto ya sucede porque solo tomamos mitigadas de 'hist_open' (mitigadas_desde_ultimo).
        # hist_mitig contiene las ya mitigadas, y como no se agregan a ninguna salida, no se muestran.
        
        mask_mitig_in_new = (
            hist_mitig["key_hash"].astype(str).isin(set_new_scan_keys) | 
            hist_mitig["key_hash_nb"].astype(str).isin(set_new_scan_keys) |
            hist_mitig["key_hash_no_out"].astype(str).isin(set_new_scan_keys) |
            hist_mitig["key_hash_nb_no_out"].astype(str).isin(set_new_scan_keys)
        )
        ya_mitigadas_y_ausentes = hist_mitig[~mask_mitig_in_new].copy()
        hist_debug = df_hist_raw.copy()
        nuevo_debug = df_new_raw.copy()
    else:
        hist_debug = None
        nuevo_debug = None

        # Infra logic with "Actualizada" support
        hist_open_id_map = {str(r.get("key_hash_identity", "")): str(r.get("Plugin Output", "")) for _, r in hist_open.iterrows() if str(r.get("key_hash_identity", ""))}
        
        set_mitig_full = set(hist_mitig["key_hash"].astype(str))
        set_mitig_id = (
            set(hist_mitig["key_hash_identity"].astype(str)) | 
            set(hist_mitig["key_id_ip"].astype(str)) | 
            set(hist_mitig["key_id_host"].astype(str))
        )
        
        set_open_full = set(hist_open["key_hash"].astype(str))
        set_open_id = (
            set(hist_open["key_hash_identity"].astype(str)) | 
            set(hist_open["key_id_ip"].astype(str)) | 
            set(hist_open["key_id_host"].astype(str))
        )

        def classify_row_infra(row):
            k = str(row["key_hash"])
            k_id = str(row["key_hash_identity"])
            k_ip = str(row["key_id_ip"])
            k_host = str(row["key_id_host"])
            
            # Diagnóstico mejorado para acuacarapps / acuagis
            ip_val = str(row.get("IP Address", ""))
            h_val = str(row.get("Host", ""))
            name_val = str(row.get("Name", ""))
            if any(x in ip_val.lower() or x in h_val.lower() for x in ["acuacarapps", "acuagis"]):
                with open("/tmp/match_debug.log", "a") as f_log:
                    f_log.write(f"[NEW INFRA DEBUG] Name='{name_val}' | Host='{h_val}' | IP='{ip_val}' | Port='{row.get('Port')}'\n")
                    f_log.write(f"                  Key={k} | Identity={k_id}\n")
                    f_log.write(f"                  In Open Full? {k in set_open_full} | In Open ID? {k_id in set_open_id or k_ip in set_open_id or k_host in set_open_id}\n")
                    f_log.write(f"                  In Mitig Full? {k in set_mitig_full} | In Mitig ID? {k_id in set_mitig_id or k_ip in set_mitig_id or k_host in set_mitig_id}\n")

            # 1. Persistente: Coincidencia exacta (incluye output)
            if k in set_open_full:
                return "P", ""
            
            # 2. Actualizada o Persistente (Fallback): Coincidencia de identidad
            old_out = ""
            if k_id in hist_open_id_map: old_out = hist_open_id_map[k_id]
            elif k_ip in hist_open_id_map: old_out = hist_open_id_map[k_ip]
            elif k_host in hist_open_id_map: old_out = hist_open_id_map[k_host]
            
            if old_out:
                current_out = str(row.get("Plugin Output", "")).strip().lower()
                if old_out.strip().lower() == current_out:
                    return "P", ""
                return "A", old_out
            
            # 3. Reabierta: Coincidencia con mitigada (exacta o identidad)
            if (k in set_mitig_full or k_id in set_mitig_id or 
                k_ip in set_mitig_id or k_host in set_mitig_id):
                return "R", ""
            
            return "N", ""

        res = nuevo_k.apply(classify_row_infra, axis=1)
        nuevo_k["__class"] = [r[0] for r in res]
        nuevo_k["Old_Output"] = [r[1] for r in res]

        persistentes = nuevo_k[nuevo_k["__class"] == "P"].copy()
        actualizadas = nuevo_k[nuevo_k["__class"] == "A"].copy()
        reabiertas = nuevo_k[nuevo_k["__class"] == "R"].copy()
        nuevas = nuevo_k[nuevo_k["__class"] == "N"].copy()

        set_new_full = set(nuevo_k["key_hash"].astype(str))
        set_new_id = set(nuevo_k["key_hash_identity"].astype(str))
        
        mask_in_new = hist_open["key_hash"].astype(str).isin(set_new_full) | hist_open["key_hash_identity"].astype(str).isin(set_new_id)
        mitigadas_desde_ultimo = hist_open[~mask_in_new].copy()
        
        mask_mitig_in_new = hist_mitig["key_hash"].astype(str).isin(set_new_full) | hist_mitig["key_hash_identity"].astype(str).isin(set_new_id)
        ya_mitigadas_y_ausentes = hist_mitig[~mask_mitig_in_new].copy()

    # Resumen
    resumen_rows = [
        ("Tipo de análisis", tipo),
        ("Min risk aplicado", min_risk),
    ]
    resumen_rows.extend([
        ("Total NUEVO (post filtro)", len(nuevo)),
        ("Total NUEVO deduplicado", len(nuevo_k)),
        ("Total HISTÓRICO (post filtro)", len(hist)),
        ("Total HISTÓRICO deduplicado", len(hist_k)),
        ("Cantidad mitigadas (Historial)", len(hist_mitig)),
        ("Cantidad no mitigadas (Historial)", len(hist_open)),
        ("Nuevas", len(nuevas)),
        ("Persistentes", len(persistentes)),
        ("Actualizadas", len(actualizadas)),
        ("Reabiertas", len(reabiertas)),
        ("Mitigadas desde último escaneo", len(mitigadas_desde_ultimo)),
        ("Mitigadas ausentes en nuevo escaneo", len(ya_mitigadas_y_ausentes)),
        ("Filas NUEVO sin clave", len(nuevo_no_key)),
        ("Filas HIST sin clave", len(hist_no_key)),
    ])

    if tipo == "ot":
        # Sumamos todo lo que está "abierto" actualmente para las métricas de detección
        activas = pd.concat([nuevas, persistentes, actualizadas, reabiertas], ignore_index=True)
        risk_counts = activas["Riesgo_ES"].value_counts(dropna=False).to_dict()
    else:
        activas = pd.concat([nuevas, persistentes, actualizadas, reabiertas], ignore_index=True)
        risk_counts = activas["Riesgo_ES"].value_counts(dropna=False).to_dict()
        
    label_map = {"critico": "críticas", "alto": "altas", "medio": "medias"}
    for k in ["critico", "alto", "medio"]:
        if tipo == "ot":
            resumen_rows.append((f"Detecciones {label_map[k]}", int(risk_counts.get(k, 0))))
        else:
            resumen_rows.append((f"Nuevas ({k})", int(risk_counts.get(k, 0))))

    resumen = pd.DataFrame(resumen_rows, columns=["Métrica", "Valor"])

    # Build summary dict for JSON API
    # El usuario solicitó que las detecciones por nivel de riesgo reflejen ÚNICA Y EXCLUSIVAMENTE
    # los niveles de riesgo del NUEVO escaneo (nuevo_k), sin importar si son persistentes, nuevas, o reabiertas.
    # No se deben incluir mitigadas u otras fuentes del histórico.
    risk_counts_all = nuevo_k["Riesgo_ES"].value_counts(dropna=False).to_dict() if not nuevo_k.empty else {}

    logger.info(f"[DASHBOARD DEBUG] tipo={tipo}")
    logger.info(f"[DASHBOARD DEBUG] len(nuevas)={len(nuevas)}, len(persistentes)={len(persistentes)}, len(actualizadas)={len(actualizadas)}, len(reabiertas)={len(reabiertas)}, len(mitigadas)={len(mitigadas_desde_ultimo)}")
    logger.info(f"[DASHBOARD DEBUG] len(nuevo_k)={len(nuevo_k) if not nuevo_k.empty else 0}")
    logger.info(f"[DASHBOARD DEBUG] risk_counts_all={risk_counts_all}")
    if not nuevo_k.empty:
        logger.info(f"[DASHBOARD DEBUG] Riesgo_ES unique values: {nuevo_k['Riesgo_ES'].unique()[:10]}")

    # Preparar lista detallada de vulnerabilidades para el dashboard
    detalles = []
    scan_date = datetime.now().strftime("%Y-%m-%d")
    
    # helper para mapear filas a dict orientados al frontend
    def _add_to_details(df_source, status_label):
        if df_source.empty: return
        for _, row in df_source.iterrows():
            if len(detalles) >= 500: # Límite de seguridad
                break
            detalles.append({
                "name": str(row.get("Name", "")),
                "host": str(row.get("Host", "")),
                "ip": str(row.get("IP Address", "")),
                "port": str(row.get("Port", "")),
                "description": str(row.get("Description", "")),
                "plugin_output": str(row.get("Plugin Output", "")),
                "risk": str(row.get("Riesgo_ES", "")),
                "status": status_label,
                "old_output": str(row.get("Old_Output", "")) if status_label == "Actualizadas" else "",
            })
            
    _add_to_details(nuevas, "Nuevas")
    _add_to_details(persistentes, "Persistentes")
    _add_to_details(actualizadas, "Actualizadas")
    _add_to_details(reabiertas, "Reabiertas")
    _add_to_details(mitigadas_desde_ultimo, "Mitigadas")

    summary = {
        "tipo": tipo,
        "min_risk": min_risk,
        "total_nuevo": int(len(nuevo)),
        "total_nuevo_dedup": int(len(nuevo_k)),
        "total_historico": int(len(hist)),
        "total_historico_dedup": int(len(hist_k)),
        "nuevas": int(len(nuevas)),
        "persistentes": int(len(persistentes)),
        "actualizadas": int(len(actualizadas)),
        "reabiertas": int(len(reabiertas)),
        "mitigadas_desde_ultimo": int(len(mitigadas_desde_ultimo)),
        "mitigadas_ausentes": int(len(ya_mitigadas_y_ausentes)),
        "detecciones_criticas": int(risk_counts_all.get("critico", 0)),
        "detecciones_altas": int(risk_counts_all.get("alto", 0)),
        "detecciones_medias": int(risk_counts_all.get("medio", 0)),
        "detalles": detalles
    }

    # Generar Excel en memoria
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        if tipo == "ot":
            nuevas.to_excel(writer, sheet_name="Nuevas", index=False)
            mitigadas_desde_ultimo.to_excel(writer, sheet_name="Mitigadas desde último escaneo", index=False)
            actualizadas.to_excel(writer, sheet_name="Actualizadas", index=False)
            reabiertas.to_excel(writer, sheet_name="Reabiertas", index=False)
            persistentes.to_excel(writer, sheet_name="Persistentes", index=False)
            ya_mitigadas_y_ausentes.to_excel(writer, sheet_name="Mitigadas ausentes en nuevo escaneo", index=False)
            resumen.to_excel(writer, sheet_name="Resumen", index=False)
            
            if hist_debug is not None:
                hist_debug.to_excel(writer, sheet_name="Historico Normalizado (Debug)", index=False)
            if nuevo_debug is not None:
                nuevo_debug.to_excel(writer, sheet_name="Nuevo Normalizado (Debug)", index=False)
        else:
            nuevas.to_excel(writer, sheet_name="Nuevas", index=False)
            persistentes.to_excel(writer, sheet_name="Persistentes", index=False)
            actualizadas.to_excel(writer, sheet_name="Actualizadas", index=False)
            mitigadas_desde_ultimo.to_excel(writer, sheet_name="Mitigadas_Desde_Ultimo", index=False)
            reabiertas.to_excel(writer, sheet_name="Reabiertas", index=False)
            ya_mitigadas_y_ausentes.to_excel(writer, sheet_name="Hist_Mitigadas_Ausentes", index=False)
            resumen.to_excel(writer, sheet_name="Resumen", index=False)

        if len(nuevo_no_key) > 0:
            nuevo_no_key.to_excel(writer, sheet_name="Diag_Nuevo_Sin_Key", index=False)
        if len(hist_no_key) > 0:
            hist_no_key.to_excel(writer, sheet_name="Diag_Hist_Sin_Key", index=False)

    output.seek(0)
    return output, summary

