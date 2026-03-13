#!/bin/bash
# Script para iniciar la aplicación en desarrollo

echo "🚀 Iniciando Comparador de Vulnerabilidades..."

# Verificar dependencias de Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 no está instalado"
    exit 1
fi

# Verificar dependencias de Node
if ! command -v npm &> /dev/null; then
    echo "❌ npm no está instalado"
    exit 1
fi

# Directorio base
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

# Función para instalar dependencias de Python
setup_python() {
    local venv_dir="$BASE_DIR/backend/venv"
    local activate_script="$venv_dir/bin/activate"
    local requirements="$BASE_DIR/backend/requirements.txt"

    # Intentar usar venv si existe o se puede crear
    if [ ! -f "$activate_script" ]; then
        echo "📦 Intentando crear entorno virtual..."
        if python3 -m venv "$venv_dir" 2>/dev/null; then
            source "$activate_script"
            echo "📦 Instalando dependencias en venv..."
            pip install -r "$requirements"
        else
            echo "⚠️ No se pudo crear venv (posiblemente entorno gestionado)."
            echo "📦 Instalando dependencias en espacio de usuario (--user)..."
            export PATH="$PATH:$HOME/.local/bin"
            pip3 install --user --break-system-packages -r "$requirements"
        fi
    else
        source "$activate_script"
    fi
}

setup_python


# Asegurar que uvicorn esté en el PATH
export PATH="$PATH:$HOME/.local/bin"

# Iniciar backend
echo "🔧 Iniciando backend en puerto 8000..."
cd "$BASE_DIR/backend"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# Iniciar frontend
echo "🎨 Iniciando frontend en puerto 5173..."
cd "$BASE_DIR/frontend"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "✅ Aplicación iniciada:"
echo "   Frontend: http://localhost:5173"
echo "   Backend:  http://localhost:8000"
echo "   API Docs: http://localhost:8000/api/docs"
echo ""
echo "Presiona Ctrl+C para detener ambos servicios"

# Capturar señal de terminación
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" SIGINT SIGTERM

# Esperar a que terminen
wait
