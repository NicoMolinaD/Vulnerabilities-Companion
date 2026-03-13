# -*- coding: utf-8 -*-
"""
API FastAPI para comparación de vulnerabilidades.
Procesamiento en memoria, sin almacenamiento de archivos.
"""

import logging
import os
import sys
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from security import setup_security, limiter
from vuln_logic import (
    compare_vulnerabilities,
    merge_app_csvs,
    compare_all_apps,
    APLICACIONES_SOPORTADAS,
)


# -----------------------------
# Configuración de Logging
# -----------------------------
def setup_logging():
    """Configura el sistema de logging con formato detallado."""
    log_format = "[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Configurar logger raíz
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
        ]
    )
    
    # Logger específico para la aplicación
    logger = logging.getLogger("vuln_compare")
    logger.setLevel(logging.DEBUG)
    
    # Reducir logs de librerías externas
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    
    return logger


logger = setup_logging()


# Configuración
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = {".csv", ".xlsx", ".xls"}


app = FastAPI(
    title="Comparador de Vulnerabilidades",
    description="API para comparar vulnerabilidades entre escaneos nuevos y registros históricos.",
    version="1.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Configurar seguridad
setup_security(app)


@app.on_event("startup")
async def startup_event():
    logger.info("=" * 60)
    logger.info("🚀 Comparador de Vulnerabilidades iniciado")
    logger.info(f"   Versión: 1.1.0")
    logger.info(f"   Aplicaciones soportadas: {APLICACIONES_SOPORTADAS}")
    logger.info(f"   Max file size: {MAX_FILE_SIZE // (1024*1024)}MB")
    logger.info("=" * 60)


def validate_file(file: UploadFile, name: str) -> None:
    """Valida tipo y tamaño del archivo."""
    logger.debug(f"Validando archivo '{name}': filename={file.filename}")
    
    if not file.filename:
        logger.warning(f"Archivo '{name}' sin nombre")
        raise HTTPException(status_code=400, detail=f"El archivo {name} no tiene nombre.")
    
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        logger.warning(f"Extensión no permitida para '{name}': {ext}")
        raise HTTPException(
            status_code=400,
            detail=f"Formato no permitido para {name}. Permitidos: {', '.join(ALLOWED_EXTENSIONS)}"
        )
    
    logger.debug(f"Archivo '{name}' válido: {file.filename}")


def validate_csv_file(file: UploadFile, name: str) -> None:
    """Valida que sea un archivo CSV."""
    logger.debug(f"Validando CSV '{name}': filename={file.filename}")
    
    if not file.filename:
        logger.warning(f"CSV '{name}' sin nombre")
        raise HTTPException(status_code=400, detail=f"El archivo {name} no tiene nombre.")
    
    ext = os.path.splitext(file.filename)[1].lower()
    if ext != ".csv":
        logger.warning(f"Archivo '{name}' no es CSV: {ext}")
        raise HTTPException(status_code=400, detail=f"El archivo {name} debe ser CSV.")
    
    logger.debug(f"CSV '{name}' válido: {file.filename}")


@app.get("/api/health")
async def health_check():
    """Endpoint de health check."""
    logger.debug("Health check solicitado")
    return {"status": "ok", "service": "vuln-compare", "timestamp": datetime.now().isoformat()}


@app.get("/api/apps")
async def get_apps():
    """Retorna la lista de aplicaciones soportadas."""
    logger.debug("Lista de aplicaciones solicitada")
    return {"aplicaciones": APLICACIONES_SOPORTADAS}


@app.post("/api/compare")
@limiter.limit("10/minute")
async def compare(
    request: Request,
    nuevo: UploadFile = File(..., description="Archivo CSV del escaneo nuevo"),
    historico: UploadFile = File(..., description="Archivo histórico (XLSX o CSV)"),
    tipo: str = Form("infra", description="Tipo de análisis: infra, ot"),
    min_risk: str = Form("medium", description="Nivel mínimo de riesgo: medium, high o critical"),
    sheet: Optional[str] = Form(None, description="Hoja del Excel histórico (nombre o índice)"),
):
    """
    Compara vulnerabilidades entre un escaneo nuevo y un histórico.
    """
    request_id = datetime.now().strftime("%Y%m%d%H%M%S%f")[:17]
    logger.info(f"[{request_id}] POST /api/compare - tipo={tipo}, min_risk={min_risk}")
    logger.info(f"[{request_id}] Archivos: nuevo={nuevo.filename}, historico={historico.filename}")
    
    # Validar archivos
    validate_file(nuevo, "nuevo")
    validate_file(historico, "historico")
    
    # Validar tipo
    if tipo not in ["infra", "ot", "ad"]:
        logger.warning(f"[{request_id}] Tipo inválido: {tipo}")
        raise HTTPException(status_code=400, detail="Tipo debe ser 'infra', 'ot' o 'ad'.")
    
    # Validar min_risk
    if min_risk not in ["medium", "high", "critical"]:
        logger.warning(f"[{request_id}] min_risk inválido: {min_risk}")
        raise HTTPException(status_code=400, detail="min_risk debe ser: medium, high o critical.")
    
    try:
        # Leer contenido en memoria
        logger.debug(f"[{request_id}] Leyendo archivos en memoria...")
        nuevo_content = await nuevo.read()
        historico_content = await historico.read()
        
        # DEBUG SAVE
        with open("/tmp/debug_hist.xlsx", "wb") as f:
            f.write(historico_content)
        
        logger.info(f"[{request_id}] Tamaños: nuevo={len(nuevo_content)} bytes, historico={len(historico_content)} bytes")
        
        # Validar tamaño
        if len(nuevo_content) > MAX_FILE_SIZE:
            logger.warning(f"[{request_id}] Archivo nuevo excede límite: {len(nuevo_content)} > {MAX_FILE_SIZE}")
            raise HTTPException(status_code=400, detail=f"El archivo nuevo excede el límite de {MAX_FILE_SIZE // (1024*1024)}MB.")
        if len(historico_content) > MAX_FILE_SIZE:
            logger.warning(f"[{request_id}] Archivo histórico excede límite: {len(historico_content)} > {MAX_FILE_SIZE}")
            raise HTTPException(status_code=400, detail=f"El archivo histórico excede el límite de {MAX_FILE_SIZE // (1024*1024)}MB.")
        
        # Procesar comparación
        logger.info(f"[{request_id}] Iniciando comparación...")
        result, summary = compare_vulnerabilities(
            nuevo_content=nuevo_content,
            nuevo_filename=nuevo.filename or "nuevo.csv",
            historico_content=historico_content,
            historico_filename=historico.filename or "historico.xlsx",
            min_risk=min_risk,
            tipo=tipo,
            sheet=sheet,
        )
        
        output_filename = f"resultado_comparacion_{tipo}.xlsx"
        logger.info(f"[{request_id}] ✅ Comparación exitosa. Generando: {output_filename}")
        
        return Response(
            content=result.read(),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={
                "Content-Disposition": f'attachment; filename="{output_filename}"',
                "Cache-Control": "no-store, no-cache, must-revalidate, private",
            }
        )
        
    except ValueError as e:
        logger.error(f"[{request_id}] ❌ ValueError: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"[{request_id}] ❌ Error inesperado: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error procesando archivos: {str(e)}")
    finally:
        await nuevo.close()
        await historico.close()
        logger.debug(f"[{request_id}] Archivos cerrados")


@app.post("/api/merge-apps")
@limiter.limit("10/minute")
async def merge_apps(
    request: Request,
    acuagis: Optional[UploadFile] = File(None, description="CSV de Acuagis"),
    acuaprocess: Optional[UploadFile] = File(None, description="CSV de Acuaprocess"),
    documento_equivalente: Optional[UploadFile] = File(None, description="CSV de Documento Equivalente"),
    acuacar_web: Optional[UploadFile] = File(None, description="CSV de Acuacar web"),
    acuaprocess_dev: Optional[UploadFile] = File(None, description="CSV de Acuaprocess Dev"),
):
    """
    Unifica múltiples CSVs de aplicaciones en un solo archivo.
    """
    request_id = datetime.now().strftime("%Y%m%d%H%M%S%f")[:17]
    logger.info(f"[{request_id}] POST /api/merge-apps")
    
    try:
        app_files = {}
        files_to_close = []
        
        file_mapping = {
            "Acuagis": acuagis,
            "Acuaprocess": acuaprocess,
            "Documento Equivalente": documento_equivalente,
            "Acuacar web": acuacar_web,
            "Acuaprocess Dev": acuaprocess_dev,
        }
        
        for app_name, file in file_mapping.items():
            if file and file.filename:
                logger.debug(f"[{request_id}] Procesando CSV de {app_name}: {file.filename}")
                validate_csv_file(file, app_name)
                content = await file.read()
                logger.info(f"[{request_id}] {app_name}: {len(content)} bytes")
                if len(content) > MAX_FILE_SIZE:
                    logger.warning(f"[{request_id}] {app_name} excede límite")
                    raise HTTPException(status_code=400, detail=f"El archivo de {app_name} excede el límite de {MAX_FILE_SIZE // (1024*1024)}MB.")
                app_files[app_name] = content
                files_to_close.append(file)
        
        if not app_files:
            logger.warning(f"[{request_id}] No se proporcionaron archivos CSV")
            raise HTTPException(status_code=400, detail="Debe proporcionar al menos un archivo CSV.")
        
        logger.info(f"[{request_id}] Unificando {len(app_files)} CSVs: {list(app_files.keys())}")
        result = merge_app_csvs(app_files)
        
        logger.info(f"[{request_id}] ✅ Unificación exitosa")
        
        return Response(
            content=result.read(),
            media_type="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="escaneo_unificado.csv"',
                "Cache-Control": "no-store, no-cache, must-revalidate, private",
            }
        )
        
    except ValueError as e:
        logger.error(f"[{request_id}] ❌ ValueError: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"[{request_id}] ❌ Error inesperado: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error unificando archivos: {str(e)}")
    finally:
        for file in files_to_close:
            await file.close()


@app.post("/api/compare-all-apps")
@limiter.limit("10/minute")
async def compare_all_apps_endpoint(
    request: Request,
    historico: UploadFile = File(..., description="Archivo histórico (XLSX o CSV)"),
    min_risk: str = Form("medium", description="Nivel mínimo de riesgo"),
    sheet: Optional[str] = Form(None, description="Hoja del Excel histórico"),
    # CSVs de cada aplicación
    acuagis: Optional[UploadFile] = File(None, description="CSV de Acuagis"),
    acuaprocess: Optional[UploadFile] = File(None, description="CSV de Acuaprocess"),
    documento_equivalente: Optional[UploadFile] = File(None, description="CSV de Documento Equivalente"),
    acuacar_web: Optional[UploadFile] = File(None, description="CSV de Acuacar web"),
    acuaprocess_dev: Optional[UploadFile] = File(None, description="CSV de Acuaprocess Dev"),
):
    """
    Unifica CSVs de todas las aplicaciones y los compara contra el histórico.
    """
    request_id = datetime.now().strftime("%Y%m%d%H%M%S%f")[:17]
    logger.info(f"[{request_id}] POST /api/compare-all-apps - min_risk={min_risk}, sheet={sheet}")
    logger.info(f"[{request_id}] Histórico: {historico.filename}")
    
    try:
        validate_file(historico, "historico")
        
        if min_risk not in ["medium", "high", "critical"]:
            logger.warning(f"[{request_id}] min_risk inválido: {min_risk}")
            raise HTTPException(status_code=400, detail="min_risk debe ser: medium, high o critical.")
        
        app_files = {}
        files_to_close = [historico]
        
        file_mapping = {
            "Acuagis": acuagis,
            "Acuaprocess": acuaprocess,
            "Documento Equivalente": documento_equivalente,
            "Web Acuacar": acuacar_web,
            "Acuaprocess Desarrollo": acuaprocess_dev,
        }
        
        for app_name, file in file_mapping.items():
            if file and file.filename:
                logger.debug(f"[{request_id}] Procesando CSV de {app_name}: {file.filename}")
                validate_csv_file(file, app_name)
                content = await file.read()
                logger.info(f"[{request_id}] {app_name}: {len(content)} bytes")
                if len(content) > MAX_FILE_SIZE:
                    logger.warning(f"[{request_id}] {app_name} excede límite")
                    raise HTTPException(status_code=400, detail=f"El archivo de {app_name} excede el límite.")
                app_files[app_name] = content
                files_to_close.append(file)
        
        if not app_files:
            logger.warning(f"[{request_id}] No se proporcionaron CSVs de aplicaciones")
            raise HTTPException(status_code=400, detail="Debe proporcionar al menos un archivo CSV de aplicación.")
        
        logger.info(f"[{request_id}] Aplicaciones recibidas: {list(app_files.keys())}")
        
        # Unificar CSVs primero
        logger.info(f"[{request_id}] Paso 1: Unificando CSVs...")
        merged_csv = merge_app_csvs(app_files)
        merged_content = merged_csv.read()
        logger.info(f"[{request_id}] CSV unificado: {len(merged_content)} bytes")
        
        # Leer histórico
        logger.info(f"[{request_id}] Paso 2: Leyendo histórico...")
        historico_content = await historico.read()
        logger.info(f"[{request_id}] Histórico: {len(historico_content)} bytes")
        
        if len(historico_content) > MAX_FILE_SIZE:
            logger.warning(f"[{request_id}] Histórico excede límite")
            raise HTTPException(status_code=400, detail=f"El archivo histórico excede el límite.")
        
        # Comparar todas las aplicaciones
        logger.info(f"[{request_id}] Paso 3: Comparando todas las aplicaciones...")
        result, _summary = compare_all_apps(
            merged_csv_content=merged_content,
            historico_content=historico_content,
            historico_filename=historico.filename or "historico.xlsx",
            min_risk=min_risk,
            sheet=sheet,
        )
        
        logger.info(f"[{request_id}] ✅ Comparación consolidada exitosa")
        
        return Response(
            content=result.read(),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={
                "Content-Disposition": 'attachment; filename="resultado_todas_aplicaciones.xlsx"',
                "Cache-Control": "no-store, no-cache, must-revalidate, private",
            }
        )
        
    except ValueError as e:
        logger.error(f"[{request_id}] ❌ ValueError: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"[{request_id}] ❌ Error inesperado: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error procesando archivos: {str(e)}")
    finally:
        for file in files_to_close:
            await file.close()
        logger.debug(f"[{request_id}] Archivos cerrados")


@app.post("/api/compare-unified-apps")
@limiter.limit("10/minute")
async def compare_unified_apps_endpoint(
    request: Request,
    unificado: UploadFile = File(..., description="Archivo CSV unificado (resultado de merge)"),
    historico: UploadFile = File(..., description="Archivo histórico (XLSX o CSV)"),
    min_risk: str = Form("medium", description="Nivel mínimo de riesgo"),
    sheet: Optional[str] = Form(None, description="Hoja del Excel histórico"),
):
    """
    Compara un CSV unificado previamente (vía /api/merge-apps) contra el histórico.
    """
    request_id = datetime.now().strftime("%Y%m%d%H%M%S%f")[:17]
    logger.info(f"[{request_id}] POST /api/compare-unified-apps - min_risk={min_risk}, sheet={sheet}")
    logger.info(f"[{request_id}] Archivos: unificado={unificado.filename}, historico={historico.filename}")
    
    try:
        validate_csv_file(unificado, "unificado")
        validate_file(historico, "historico")
        
        if min_risk not in ["medium", "high", "critical"]:
            logger.warning(f"[{request_id}] min_risk inválido: {min_risk}")
            raise HTTPException(status_code=400, detail="min_risk debe ser: medium, high o critical.")
        
        # Leer contenidos
        unificado_content = await unificado.read()
        historico_content = await historico.read()
        
        logger.info(f"[{request_id}] Tamaños: unificado={len(unificado_content)} bytes, historico={len(historico_content)} bytes")
        
        # Comparar todas las aplicaciones
        logger.info(f"[{request_id}] Comparando desde unificado...")
        result, _summary = compare_all_apps(
            merged_csv_content=unificado_content,
            historico_content=historico_content,
            historico_filename=historico.filename or "historico.xlsx",
            min_risk=min_risk,
            sheet=sheet,
        )
        
        logger.info(f"[{request_id}] ✅ Comparación exitosa")
        
        return Response(
            content=result.read(),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={
                "Content-Disposition": 'attachment; filename="resultado_comparativo_apps.xlsx"',
                "Cache-Control": "no-store, no-cache, must-revalidate, private",
            }
        )
        
    except ValueError as e:
        logger.error(f"[{request_id}] ❌ ValueError: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"[{request_id}] ❌ Error inesperado: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error procesando archivos: {str(e)}")
    finally:
        await unificado.close()
        await historico.close()
        logger.debug(f"[{request_id}] Archivos cerrados")


@app.post("/api/compare-unified-apps-json")
@limiter.limit("10/minute")
async def compare_unified_apps_json_endpoint(
    request: Request,
    unificado: UploadFile = File(..., description="Archivo CSV unificado (resultado de merge)"),
    historico: UploadFile = File(..., description="Archivo histórico (XLSX o CSV)"),
    min_risk: str = Form("medium", description="Nivel mínimo de riesgo"),
    sheet: Optional[str] = Form(None, description="Hoja del Excel histórico"),
):
    """
    Compara un CSV unificado y retorna el JSON summary en vez del Excel.
    """
    request_id = datetime.now().strftime("%Y%m%d%H%M%S%f")[:17]
    logger.info(f"[{request_id}] POST /api/compare-unified-apps-json - min_risk={min_risk}, sheet={sheet}")
    
    try:
        validate_csv_file(unificado, "unificado")
        validate_file(historico, "historico")
        
        if min_risk not in ["medium", "high", "critical"]:
            logger.warning(f"[{request_id}] min_risk inválido: {min_risk}")
            raise HTTPException(status_code=400, detail="min_risk debe ser: medium, high o critical.")
        
        unificado_content = await unificado.read()
        historico_content = await historico.read()
        
        logger.info(f"[{request_id}] Comparando desde unificado para JSON...")
        _excel_result, summary = compare_all_apps(
            merged_csv_content=unificado_content,
            historico_content=historico_content,
            historico_filename=historico.filename or "historico.xlsx",
            min_risk=min_risk,
            sheet=sheet,
        )
        
        logger.info(f"[{request_id}] ✅ Comparación JSON (Apps) exitosa")
        return JSONResponse(content=summary)
        
    except ValueError as e:
        logger.error(f"[{request_id}] ❌ ValueError: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"[{request_id}] ❌ Error inesperado: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error procesando archivos: {str(e)}")
    finally:
        await unificado.close()
        await historico.close()


@app.post("/api/compare-json")
@limiter.limit("10/minute")
async def compare_json(
    request: Request,
    nuevo: UploadFile = File(..., description="Archivo CSV del escaneo nuevo"),
    historico: UploadFile = File(..., description="Archivo histórico (XLSX o CSV)"),
    tipo: str = Form("infra", description="Tipo de análisis: infra, ot"),
    min_risk: str = Form("medium", description="Nivel mínimo de riesgo: medium, high o critical"),
    sheet: Optional[str] = Form(None, description="Hoja del Excel histórico"),
):
    """
    Compara vulnerabilidades y retorna un resumen JSON con métricas para visualización.
    """
    request_id = datetime.now().strftime("%Y%m%d%H%M%S%f")[:17]
    logger.info(f"[{request_id}] POST /api/compare-json - tipo={tipo}, min_risk={min_risk}")
    
    validate_file(nuevo, "nuevo")
    validate_file(historico, "historico")
    
    if tipo not in ["infra", "ot", "ad"]:
        raise HTTPException(status_code=400, detail="Tipo debe ser 'infra', 'ot' o 'ad'.")
    if min_risk not in ["medium", "high", "critical"]:
        raise HTTPException(status_code=400, detail="min_risk debe ser: medium, high o critical.")
    
    try:
        nuevo_content = await nuevo.read()
        historico_content = await historico.read()
        
        if len(nuevo_content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail=f"El archivo nuevo excede el límite de {MAX_FILE_SIZE // (1024*1024)}MB.")
        if len(historico_content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail=f"El archivo histórico excede el límite de {MAX_FILE_SIZE // (1024*1024)}MB.")
        
        # DEBUG SAVE
        with open("/tmp/debug_hist.xlsx", "wb") as f:
            f.write(historico_content)
            
        _excel, summary = compare_vulnerabilities(
            nuevo_content=nuevo_content,
            nuevo_filename=nuevo.filename or "nuevo.csv",
            historico_content=historico_content,
            historico_filename=historico.filename or "historico.xlsx",
            min_risk=min_risk,
            tipo=tipo,
            sheet=sheet,
        )
        
        logger.info(f"[{request_id}] ✅ Comparación JSON exitosa")
        return JSONResponse(content=summary)
        
    except ValueError as e:
        logger.error(f"[{request_id}] ❌ ValueError: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"[{request_id}] ❌ Error inesperado: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error procesando archivos: {str(e)}")
    finally:
        await nuevo.close()
        await historico.close()


# Servir frontend en producción
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.exists(frontend_path):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_path, "assets")), name="assets")
    
    @app.get("/", response_class=HTMLResponse)
    async def serve_frontend():
        with open(os.path.join(frontend_path, "index.html"), "r") as f:
            return f.read()


if __name__ == "__main__":
    import uvicorn
    logger.info("Iniciando servidor en modo standalone...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
