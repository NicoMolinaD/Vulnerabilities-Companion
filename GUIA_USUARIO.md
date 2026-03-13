## Comparador de Vulnerabilidades – Guía de Usuario

Esta guía cubre el uso completo del sistema de comparación de vulnerabilidades, tanto para usuarios funcionales como para administradores técnicos (devops / infra).

---

## 1. Descripción General

El sistema permite:

- **Comparar un escaneo nuevo** contra un **histórico** (infraestructura, OT y AD).
- **Unificar múltiples CSV de aplicaciones** en un solo archivo normalizado.
- **Realizar análisis consolidados de aplicaciones** frente a un histórico.
- **Visualizar métricas y detalles de vulnerabilidades** de forma interactiva e intuitiva en la interfaz web.
- **Descargar el resultado completo en Excel** para tratamiento posterior.

Tecnologías principales:

- Backend: **FastAPI (Python 3.11)**.
- Frontend: **React + Vite (TypeScript)**.
- Despliegue: **Docker + docker-compose + Nginx**.

---

## 2. Estructura del Proyecto

- `backend/`
  - `main.py`: API FastAPI, endpoints de comparación y salud.
  - `vuln_logic.py`: lógica de comparación / unificación.
  - `requirements.txt`: dependencias de Python.
- `frontend/`
  - `src/App.tsx`: interfaz principal y tablero de resultados.
  - `src/index.css`: estilos del sistema.
  - `nginx.conf`: configuración de Nginx para servir el frontend y hacer proxy al backend.
- `docker-compose.yml`: orquestación de contenedores backend + frontend (Nginx).
- `backend/Dockerfile`: imagen del backend.
- `frontend/Dockerfile`: build del frontend y empaquetado con Nginx.
- `.env.example`: ejemplo de variables de entorno.
- `.gitignore`: exclusión de `.env`, artefactos de build y dependencias.

---

## 3. Variables de Entorno

El archivo `.env` **no se versiona** (está en `.gitignore`). Use `.env.example` como referencia:

- **Backend**
  - `BACKEND_PORT` (por defecto `8000`): puerto de exposición interno del backend.

- **Frontend**
  - `VITE_API_URL` (por defecto `/api`): URL base para las peticiones API.  
    - En despliegue con Nginx y docker-compose se usa `/api`, que es proxyeado al backend.

### 3.1. Creación del `.env`

1. Copiar el archivo de ejemplo:

```bash
cp .env.example .env
```

2. Ajustar los valores si es necesario:

```bash
BACKEND_PORT=8000
VITE_API_URL=/api
```

En despliegue estándar con `docker-compose`, estos valores suelen ser suficientes.

---

## 4. Despliegue con Docker y Nginx

### 4.1. Requisitos Previos

- Docker instalado (v20+ recomendado).
- docker-compose (v2+ recomendado).

### 4.2. Construir y levantar los contenedores

Desde la carpeta raíz del proyecto:

```bash
docker-compose up -d --build
```

Esto hará:

- Construir la imagen del **backend** (`backend/Dockerfile`), exponiendo el puerto `8000` dentro de la red interna `app-network`.
- Construir la imagen del **frontend** (`frontend/Dockerfile`):
  - Etapa 1: build de React / Vite.
  - Etapa 2: imagen `nginx:stable-alpine` con el contenido de `dist/` y la configuración de `nginx.conf`.
- Publicar el servicio frontend (Nginx) en el host en el puerto **80** (`http://<servidor>/`).
- Configurar en Nginx el proxy `location /api/` hacia `http://backend:8000/`.

### 4.3. Verificar el estado de los contenedores

```bash
docker-compose ps
```

Ambos servicios (`vuln-backend` y `vuln-frontend`) deben aparecer como `Up`.

### 4.4. Parar los servicios

```bash
docker-compose down
```

---

## 5. Uso de la Interfaz Web

### 5.1. Acceso

- En entorno local: `http://localhost/`
- En servidor: `http://<IP-o-dominio>/`

### 5.2. Flujo general

En la pantalla principal encontrará:

- **Configuración**:
  - **Tipo de análisis**:
    - `Infraestructura` (`infra`)
    - `Directorio Activo` (`ad`)
    - `Aplicaciones` (`todas_apps`)
    - `Escaneo OT` (`ot`)
  - **Riesgo mínimo**:
    - `Medium+`
    - `High+`
    - `Critical`
  - **Hoja del Excel (opcional)**:
    - Nombre de la hoja o índice (`0, 1, 2, ...`) a utilizar para el archivo histórico.

- **Sección de archivos**:
  - Dependiendo del **tipo de análisis**, se mostrará:
    - Comparación estándar (`infra`, `ot`, `ad`).
    - Flujo en 2 pasos para **Aplicaciones** (`todas_apps`).

### 5.3. Análisis estándar (Infra / OT / AD)

1. Seleccionar **Tipo de análisis**:
   - `Infraestructura`, `Directorio Activo` o `Escaneo OT`.
2. Elegir **Riesgo mínimo**:
   - `Medium+`, `High+` o `Critical`.
3. (Opcional) Indicar **Hoja del Excel** histórico.
4. Subir:
   - `Escaneo nuevo (CSV)` – resultado reciente de la herramienta de escaneo.
   - `Histórico (Excel o CSV)` – archivo consolidado histórico (con columna de mitigación).
5. Pulsar **“Comparar y descargar”**.

El sistema:

- Enviará los archivos al backend.
- Ejecutará la lógica de comparación (incluyendo soportes específicos para `infra`, `ot` y `ad`).
- Realizará **dos peticiones en paralelo**:
  - `/api/compare-json`: devuelve el resumen JSON para la interfaz.
  - `/api/compare`: devuelve el Excel completo.
- Mostrará un **tablero interactivo** con métricas y detalle.
- Permite descargar el Excel generado desde la interfaz.

### 5.4. Análisis de Aplicaciones (`todas_apps`)

Este flujo tiene **dos pasos**:

#### Paso 1 – Normalización y Unificación

1. Seleccionar el tipo `Aplicaciones` en la sección de configuración.
2. En la tarjeta de “Paso 1: Normalización y Unificación”:
   - Subir uno o varios CSV:
     - `Acuagis`
     - `Acuaprocess`
     - `Documento Equivalente`
     - `Acuacar web`
     - `Acuaprocess Dev`
3. Pulsar **“Normalizar y Unificar”**.

El sistema:

- Enviará los CSV a `/api/merge-apps`.
- Normalizará y unificará los datos en un **único CSV**.
- Mostrará un mensaje de Paso 1 completado, junto al archivo unificado y la opción de descargarlo.

#### Paso 2 – Análisis Comparativo

1. En “Paso 2: Análisis Comparativo”:
   - Subir el **Histórico (Excel o CSV)** de aplicaciones.
2. Ajustar, si es necesario, la **Hoja del Excel** en la sección de configuración.
3. Pulsar **“Empezar análisis comparativo”**.

El sistema:

- Llamará a:
  - `/api/compare-unified-apps-json` para obtener el resumen en JSON.
  - `/api/compare-unified-apps` para obtener el Excel de resultado.
- Mostrará el tablero de resultados y permitirá descargar el Excel.

---

## 6. Tablero de Resultados

Tras un análisis exitoso, se muestra un **dashboard** con:

- **Resumen general**:
  - Tipo de análisis (`Infraestructura`, `Aplicaciones`, `Escaneo OT`, `AD`).
  - Riesgo mínimo aplicado.

- **Tarjetas de métricas**:
  - `Nuevas`
  - `Persistentes`
  - `Actualizadas`
  - `Reabiertas`
  - `Mitigadas`

- **Gráfico de dona (Clasificación)**:
  - Distribución de vulnerabilidades por estado (`Nuevas`, `Persistentes`, `Actualizadas`, `Reabiertas`).

- **Gráfico de barras horizontales (Riesgo)**:
  - `Críticas`
  - `Altas`
  - `Medias`
  - Totales de escaneadas e histórico (cuando aplica).

- **Tabla detallada de vulnerabilidades**:
  - Búsquedas por:
    - Nombre de vulnerabilidad.
    - Host.
    - IP.
  - Filtros por:
    - Riesgo.
    - Estado.
    - Puerto.
    - Aplicación (cuando el análisis es de aplicaciones).
  - Ordenamiento por columnas (clic en cabecera):
    - `Aplicación`, `Vulnerabilidad`, `Host`, `IP`, `Puerto`, `Riesgo`, `Estado`.
  - Expansión de fila:
    - Ver descripción.
    - Ver comparación de outputs (histórico vs nuevo) cuando aplica.

En el modo de **Aplicaciones**, puede seleccionar una sola aplicación para recalcular las métricas y ver el detalle filtrado.

---

## 7. Endpoints Principales del Backend

Para referencia técnica:

- `GET /api/health`
  - Health check básico.

- `GET /api/apps`
  - Lista de aplicaciones soportadas (para lógica interna).

- `POST /api/compare`
  - Comparación estándar (infra / ot / ad) y retorno de Excel.

- `POST /api/compare-json`
  - Comparación estándar y retorno de resumen JSON (métricas y detalles).

- `POST /api/merge-apps`
  - Unificación de múltiples CSV de aplicaciones en un solo CSV.

- `POST /api/compare-all-apps`
  - Unifica CSVs de aplicaciones y los compara contra el histórico, devolviendo Excel.

- `POST /api/compare-unified-apps`
  - Toma un CSV unificado + histórico y devuelve Excel.

- `POST /api/compare-unified-apps-json`
  - Igual que el anterior, pero devuelve el resumen JSON para visualización.

---

## 8. Buenas Prácticas y Límites

- **Tamaño máximo de archivos**:
  - Actualmente configurado en **10 MB** por archivo.
- **Formatos permitidos**:
  - Nuevo escaneo: **CSV**.
  - Histórico: **XLSX / XLS / CSV**.
- **Seguridad**:
  - No se almacenan archivos en disco (salvo temporalmente para depuración).
  - El procesamiento se realiza en memoria.
  - Se aplican límites de rate limit por endpoint.

---

## 9. Desarrollo Local (opcional, sin Docker)

### 9.1. Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 9.2. Frontend

```bash
cd frontend
npm install
npm run dev
```

En desarrollo, puede ajustar `VITE_API_URL` para apuntar al backend (`http://localhost:8000/api`), según su configuración.

---

## 10. Despliegue a Producción – Resumen

1. Configurar `.env` a partir de `.env.example`.
2. Asegurarse de que **`.env` NO se suba al repositorio** (`.gitignore` ya lo contempla).
3. En el servidor, clonar el repositorio:

```bash
git clone <URL_DEL_REPO>
cd <carpeta_del_repo>
cp .env.example .env  # y ajustar si es necesario
docker-compose up -d --build
```

4. Verificar acceso a la interfaz vía navegador.
5. Verificar logs si es necesario con `docker-compose logs -f`.

Con esto, el sistema queda desplegado en producción detrás de Nginx, sirviendo el frontend y exponiendo la API del backend bajo `/api`.

