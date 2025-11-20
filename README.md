# Microservicios y Datos Distribuidos.

## Arquitectura Médica con Citus.

### Proyecto completo de despliegue de una base de datos distribuida con Citus sobre Kubernetes, acompañado de un backend FastAPI escalable para manejar datos médicos.

*Nota: Todos los comandos fueron testeados en Debian GNU/Linux 13 (trixie). Se recomienda utilizar esta versión o una compatible.*

# Instalación del proyecto.

#### 1. Actualizar el sistema.
```bash
sudo apt update && sudo apt upgrade -y
```

#### 2. Instalar utilidades y herramientas de desarrollo.
```bash
sudo apt install -y curl wget git vim htop unzip ca-certificates python3 python3-pip python3-venv libcairo2 libpango-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info libjpeg-dev libxml2 libxslt1.1
```

#### 3. Crear directorio seguro para claves GPG.
```bash
sudo install -m 0755 -d /etc/apt/keyrings
```

#### 4. Importar clave GPG de Docker.
```bash
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
```

#### 5. Agregar repositorio oficial de Docker e instalar.
```bash
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker
```

#### 6. Crear variables del entorno, aquí, asgianas el nombre del proyecto, el nombre de los kubernetes, usuario y contraseña de la base de datos.
```bash
PROJECT_NAME="clinica.derwincode.com"
K8S_NAMESPACE="clinica"
PROJECT_DIR="$(xdg-user-dir DOCUMENTS)/$PROJECT_NAME"
STATIC_DIR="$PROJECT_DIR/frontend"
WEB_ROOT="$STATIC_DIR/html"
DB_USER="derwincode"
DB_PASSWORD="JOptionPane0824clinica"
DB_NAME="clinica"
COORDINATOR_HOST="citus-coordinator.$K8S_NAMESPACE.svc.cluster.local"
BACKEND_IMAGE="backend:1.0"
BACKEND_PORT="8000"
BACKEND_NODEPORT="30080"
```

#### 7. Ir a la carpeta donde se va a trabajar
```bash
cd "$(xdg-user-dir DOCUMENTS)"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"
```

#### 8. Crear estructura de directorios del proyecto.
```bash
mkdir -p \
backend/app/api/v1 backend/app/api/v1/endpoints backend/app/core backend/app/db backend/app/middleware backend/app/models backend/app/schemas backend/app/services \
frontend/html frontend/css frontend/javascript frontend/img \
k8s/citus
```

#### Configurar backend.
##### 9.1 backend/app/api/v1/endpoints/auth.py.
```bash
cat <<EOF > backend/app/api/v1/endpoints/auth.py
# backend/app/api/v1/endpoints/auth.py
from fastapi import APIRouter, HTTPException, status, Body, Depends
from app.schemas.auth import UserLogin, UserCreate, PacienteCreate
from app.services.auth_service import (
    create_user_service,
    authenticate_and_create_token,
    create_paciente_service
)
from app.core.security import get_current_user

router = APIRouter()


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserCreate):
    try:
        create_user_service(user)
    except ValueError as e:
        if str(e) == "email_exists":
            return {"status": "error", "message": "Este usuario ya existe"}
        return {"status": "error", "message": "No se ha podido registrar el usuario"}
    return {"status": "success", "message": "Usuario registrado"}


@router.post("/login")
def login(form_data: UserLogin):
    auth = authenticate_and_create_token(form_data.email, form_data.password)
    if not auth:
        return {"status": "error", "message": "No se pudo iniciar su sesión"}

    return {
        "status": "success",
        "message": "Inicio de sesión exitoso",
        "token": auth["access_token"],
        "rol": auth["user"]["rol"]
    }


@router.post("/register_paciente", status_code=201)
def register_paciente(
    payload: dict = Body(...),
    current_user: dict = Depends(get_current_user)
):
    if current_user["rol"] != "admisionista":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tiene permisos para registrar pacientes"
        )

    try:
        user_data = UserCreate(**payload.get("user"))
        paciente_data = PacienteCreate(**payload.get("paciente"))
        result = create_paciente_service(user_data, paciente_data)
    except ValueError as e:
        if str(e) == "email_exists":
            return {"status": "error", "message": "Este usuario ya existe"}
        return {"status": "error", "message": "No se pudo registrar el paciente"}

    return {"status": "success", "message": "Paciente registrado", "data": result}
EOF
```

##### 9.2 backend/app/core/security.py.
```bash
cat <<EOF > backend/app/core/security.py
# backend/app/core/security.py
import os
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from app.db.connection import query_one

PWD_CTX = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "cambiame_ya")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_password_hash(password: str) -> str:
    return PWD_CTX.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return PWD_CTX.verify(plain_password, hashed_password)


def create_access_token(subject: str, roles: str, expires_delta: int = None):
    expire = datetime.utcnow() + timedelta(
        minutes=(expires_delta if expires_delta is not None else ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode = {"sub": subject, "roles": roles, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(status_code=401, detail="Token no proporcionado")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
          raise HTTPException(status_code=401, detail="Token inválido")

        q = "SELECT id, nombre, apellido, email, rol, created_at, updated_at FROM usuario WHERE id = %s"
        user = query_one(q, (user_id,))

        if not user:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")

        return user

    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
EOF
```

##### 9.3 backend/app/db/connection.py.
```bash
cat <<EOF > backend/app/db/connection.py
# backend/app/db/connection.py
import os
import psycopg2
from psycopg2.extras import RealDictCursor

DATABASE_URL = os.getenv("DATABASE_URL")

def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL no definida")
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn

def query_one(query, params=()):
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            return cur.fetchone()
    finally:
        conn.close()

def execute(query, params=()):
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            conn.commit()
            try:
                return cur.fetchone()
            except:
                return None
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
EOF
```

##### 9.4 backend/app/middleware/middleware-deployment.yaml.
```bash
cat <<EOF > backend/app/middleware/middleware-deployment.yaml
# backend/app/middleware/middleware-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: middleware
  labels:
    app: middleware
spec:
  replicas: 1
  selector:
    matchLabels:
      app: middleware
  template:
    metadata:
      labels:
        app: middleware
    spec:
      containers:
        - name: middleware
          image: backend:1.0
          ports:
            - containerPort: 8000
          envFrom:
            - secretRef:
                name: clinica-secrets
EOF
```

##### 9.5 backend/app/schemas/auth.py.
```bash
cat <<EOF > backend/app/schemas/auth.py
# backend/app/schemas/auth.py
from pydantic import BaseModel, EmailStr, constr
from typing import Optional

class UserLogin(BaseModel):
    email: EmailStr
    password: constr(min_length=8)

class UserCreate(BaseModel):
    nombre: constr(min_length=1)
    apellido: constr(min_length=1)
    email: EmailStr
    password: constr(min_length=8)
    rol: constr(pattern="^(paciente|medico|admisionista)$")

class PacienteCreate(BaseModel):
    documento_id: constr(min_length=1)
    tipo_documento: Optional[str]
    fecha_nacimiento: str
    sexo: Optional[str]
    telefono: Optional[str]
    regimen: Optional[str]
    eps: Optional[str]
    tipo_sangre: Optional[str]

class UserOut(BaseModel):
    id: Optional[str]
    nombre: str
    apellido: str
    email: EmailStr
    rol: str
    fecha_creacion: Optional[str]

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
EOF
```

##### 9.6 backend/app/services/auth_service.py.
```bash
cat <<EOF > backend/app/services/auth_service.py
# backend/app/services/auth_service.py
from app.db.connection import query_one, execute
from app.core.security import get_password_hash, verify_password, create_access_token
from app.schemas.auth import UserCreate, PacienteCreate

def get_user_by_email(email: str):
    q = "SELECT id, nombre, apellido, email, hash_password, rol, created_at, updated_at FROM usuario WHERE email = %s"
    return query_one(q, (email,))

def create_user_service(user_in: UserCreate):
    existing = get_user_by_email(user_in.email)
    if existing:
        raise ValueError("email_exists")

    hashed = get_password_hash(user_in.password)
    q = """
    INSERT INTO usuario (nombre, apellido, email, hash_password, rol)
    VALUES (%s, %s, %s, %s, %s)
    RETURNING id, nombre, apellido, email, rol, created_at, updated_at
    """
    row = execute(q, (user_in.nombre, user_in.apellido, user_in.email, hashed, user_in.rol))
    if not row:
        return get_user_by_email(user_in.email)
    return row

def authenticate_and_create_token(email: str, password: str):
    user = get_user_by_email(email)
    if not user:
        return None
    if not verify_password(password, user["hash_password"]):
        return None
    token = create_access_token(subject=str(user["id"]), roles=user["rol"])
    return {"access_token": token, "user": user}

def create_paciente_service(user_in: UserCreate, paciente_in: PacienteCreate):
    user = create_user_service(user_in)
    usuario_id = user["id"]

    q = """
    INSERT INTO paciente (
        documento_id, tipo_documento, fecha_nacimiento, sexo,
        telefono, regimen, eps, tipo_sangre, usuario_id
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    RETURNING id, usuario_id, created_at, updated_at
    """

    params = (
        paciente_in.documento_id,
        paciente_in.tipo_documento,
        paciente_in.fecha_nacimiento,
        paciente_in.sexo,
        paciente_in.telefono,
        paciente_in.regimen,
        paciente_in.eps,
        paciente_in.tipo_sangre,
        usuario_id
    )

    paciente = execute(q, params)
    return {"usuario": user, "paciente": paciente}
EOF
```

##### 9.7 backend/app/main.py.
```bash
cat <<EOF > backend/app/main.py
# backend/app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.db.connection import query_one
from app.api.v1.endpoints import auth

app = FastAPI()

origins = [
    "https://clinica.derwincode.com",
    "https://apiclinica.derwincode.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/ping")
def ping():
    try:
        result = query_one("SELECT 1;")
        return {"pong": result["?column?"]}
    except Exception as e:
        return {"error": str(e)}

app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
EOF
```

#### 9.8 Crear archivo __init__.py
```bash
cat <<EOF > backend/__init__.py
# backend/app/__init__.py
EOF
```

##### 9.9 Dockerfile.
```bash
cat <<EOF > backend/Dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       libpq-dev \
       libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install bcrypt==4.1.2

COPY . .

ARG BACKEND_PORT=8000
ENV BACKEND_PORT=${BACKEND_PORT}

EXPOSE ${BACKEND_PORT}

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "${BACKEND_PORT}"]
EOF
```

##### 9.10 backend/requirements.txt.
```bash
cat <<EOF > backend/requirements.txt
fastapi
uvicorn
psycopg2-binary
python-dotenv
pydantic
python-jose[cryptography]
passlib[bcrypt]
python-multipart
Jinja2
WeasyPrint
email-validator
bcrypt==4.1.2
EOF
```

#### Configurar el frontend
##### 10.1 frontend/css/admisionista.css.
```bash
cat <<'EOF' > frontend/css/admisionista.css
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: 'Poppins', sans-serif;
}

body {
    background: linear-gradient(160deg,#f4f7fb,#e0e6f1);
    color: #1a1a1a;
}

:root {
    --azul-primario: #0ea5e9;
    --azul-oscuro: #0b4870;
    --gris-suave: #f0f2f5;
    --blanco: #ffffff;
    --negro: #121212;
    --rojo: #e63946;
    --gris-input: #f8f9fb;
    --sombra: rgba(0,0,0,0.15);
}

.sidebar {
    width: 240px;
    height: 100vh;
    background: linear-gradient(180deg, #0b4870, #0e6fb8);
    padding: 25px 20px;
    position: fixed;
    top: 0;
    left: 0;
    color: var(--blanco);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    border-radius: 0 20px 20px 0;
    transition: left 0.3s;
    box-shadow: 2px 0 20px rgba(0,0,0,0.2);
    backdrop-filter: blur(10px);
}

.sidebar h2 {
    font-size: 1.7em;
    text-align: center;
    margin-bottom: 30px;
    letter-spacing: 1px;
    text-shadow: 0 2px 6px rgba(0,0,0,0.3);
}

.sidebar ul {
    list-style: none;
    padding: 0;
}

.sidebar ul li {
    padding: 12px 16px;
    margin-bottom: 12px;
    border-radius: 12px;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 0.95em;
    transition: all 0.3s;
    background: rgba(255,255,255,0.05);
}

.sidebar ul li:hover {
    background: rgba(255,255,255,0.2);
    transform: translateX(4px);
}

.sidebar ul li.active {
    background: var(--azul-primario);
    box-shadow: 0 4px 15px var(--sombra);
}

.sidebar .logout {
    background: var(--rojo);
    padding: 10px;
    border-radius: 12px;
    font-weight: 500;
    cursor: pointer;
    text-align: center;
    transition: all 0.3s;
    font-size: 0.95em;
}

.sidebar .logout:hover {
    background: #c92c35;
}

.main-content {
    margin-left: 240px;
    padding: 25px 30px;
    transition: margin-left 0.3s;
}

header h1 {
    font-size: 2em;
    color: var(--azul-oscuro);
    margin-bottom: 25px;
    text-shadow: 0 2px 6px rgba(0,0,0,0.1);
}

.card {
    background: var(--blanco);
    padding: 25px 20px;
    border-radius: 20px;
    box-shadow: 0 8px 20px var(--sombra);
    margin-bottom: 20px;
    transition: transform 0.3s, box-shadow 0.3s;
}

.card:hover {
    transform: translateY(-3px);
    box-shadow: 0 12px 28px var(--sombra);
}

.card h3 {
    margin-bottom: 15px;
    font-size: 1.4em;
    color: var(--azul-oscuro);
}

.form-grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 15px;
}

.form-grid-2 input,
.form-grid-2 select {
    width: 100%;
    padding: 12px 16px;
    border-radius: 15px;
    border: none;
    background: var(--gris-input);
    font-size: 0.95em;
    box-shadow: inset 0 2px 6px rgba(0,0,0,0.05);
    transition: all 0.3s;
}

.form-grid-2 input:focus,
.form-grid-2 select:focus {
    outline: none;
    box-shadow: 0 0 6px rgba(14,165,233,0.4);
}

.form-grid-2 button,
.btn-primary {
    background: linear-gradient(135deg,#0ea5e9,#0284c7);
    color: #fff;
    border: none;
    padding: 8px 20px;
    font-size: 0.95em;
    border-radius: 12px;
    cursor: pointer;
    font-weight: 600;
    transition: all 0.3s;
    justify-self: start;
    box-shadow: 0 4px 12px var(--sombra);
}

.form-grid-2 button:hover,
.btn-primary:hover {
    transform: translateY(-1px);
    box-shadow: 0 6px 18px var(--sombra);
    background: linear-gradient(135deg,#0284c7,#0ea5e9);
}

.table {
    width: 100%;
    border-collapse: collapse;
    border-radius: 15px;
    overflow: hidden;
    box-shadow: 0 6px 18px var(--sombra);
    margin-top: 15px;
}

.table th, .table td {
    padding: 10px 12px;
    text-align: left;
}

thead {
    background: var(--azul-primario);
    color: var(--blanco);
}

tbody tr:nth-child(even) {
    background: var(--gris-suave);
}

tbody tr:hover {
    background: #d0ebff;
}

.vista {
    display: none;
}

.vista.active {
    display: block;
}

@media (max-width: 900px) {
    .sidebar { width: 200px; }
    .main-content { margin-left: 200px; }
}

@media (max-width: 650px) {
    .sidebar {
        position: absolute;
        left: -250px;
        z-index: 1000;
    }
    .sidebar.active {
        left: 0;
    }
    .main-content {
        margin-left: 0;
        padding: 15px;
    }
    .form-grid-2 {
        grid-template-columns: 1fr;
    }
    
}
EOF
```

##### 10.2 frontend/css/index.css.
```bash
cat <<'EOF' > frontend/css/index.css
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap');

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
  font-family: 'Poppins', sans-serif;
}

body {
  background: #121212;
}

.wrapper {
  width: 400px;
  max-width: 95%;
  background: #1f1f1f;
  border-radius: 12px;
  padding: 25px;
  transition: 0.3s ease;
}

h2 {
  color: #ffffff;
  font-size: 2em;
  margin-bottom: 5px;
  text-align: center;
}

.logo {
  width: 100px;
  height: 100px;
  object-fit: contain;
  filter: drop-shadow(0 0 3px #0ea5e9);
  margin: 0 auto;
}

.icon {
  position: absolute;
  left: 10px;
  top: 50%;
  transform: translateY(-40%);
  color: #0ea5e9;
  font-size: 1.2em;
  pointer-events: none;
}

.eye-icon {
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translateY(-40%);
  cursor: pointer;
  color: #0ea5e9;
  font-size: 1.5em;
}

.form-control {
  padding-left: 40px;
  height: 50px;
  background: #2a2a2a !important;
  border: 1px solid #3a3a3a !important;
  color: #ffffff !important;
  border-radius: 8px;
}

.form-control::placeholder {
  color: #e0e0e0 !important;
  opacity: 1 !important;
}

.btn {
  background: #0ea5e9 !important;
  border: none !important;
  border-radius: 8px !important;
  height: 45px;
  font-weight: 500;
  transition: background 0.3s;
}

.btn:hover {
  background: #0284c7 !important;
}

.form {
  display: none;
  opacity: 0;
  transition: opacity .4s ease;
}

.form.active {
  display: block;
  opacity: 1;
}

@media (max-width:414px) {
  .wrapper {
    width: 90%;
  }

  .form-control,
  .btn {
    height: 40px;
    font-size: 0.9em;
  }
}
EOF
```

##### 10.3 frontend/html/admisionista.html.
```bash
cat <<'EOF' > frontend/html/admisionista.html
<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Panel Admisionista</title>
    <link rel="stylesheet" href="/css/admisionista.css">
    <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/toastify-js" defer></script>
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.css" />
    <style>
        .form-grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }

        .form-grid-2 button {
            grid-column: span 2;
        }
    </style>
</head>

<body>

    <div class="sidebar">
        <h2>Admisionista</h2>

        <ul>
            <li class="active" onclick="mostrarVista('vistaRegistrarPaciente')">Registrar Paciente</li>
            <li onclick="mostrarVista('vistaInternados')">Pacientes Internados</li>
            <li onclick="mostrarVista('vistaAsignarCita')">Asignar Cita</li>
            <li onclick="mostrarVista('vistaVerCitas')">Ver Citas</li>
            <li onclick="mostrarVista('vistaMedicos')">Médicos</li>
            <li onclick="mostrarVista('vistaHistoria')">Historia Clínica</li>
        </ul>
        <button class="btn-primary logout">Cerrar sesión</button>
    </div>

    <div class="main-content">
        <header>
            <h1>Panel de Gestión</h1>
        </header>

        <div id="vistaRegistrarPaciente" class="vista active">
            <div class="card">
                <h3>Registrar Paciente</h3>
                <form id="registro-form" class="form-grid-2">
                    <input type="text" name="nombre" id="pNombre" placeholder="Nombres" required>
                    <input type="text" name="apellido" id="pApellidos" placeholder="Apellidos" required>

                    <select name="tipo_documento" id="pTipoDoc" required>
                        <option value="">Tipo de documento</option>
                        <option>CC</option>
                        <option>TI</option>
                        <option>CE</option>
                        <option>RC</option>
                    </select>

                    <input type="text" name="documento_id" id="pDocumento" placeholder="Número de documento" required>
                    <input type="password" name="password" id="pContrasena" placeholder="Contraseña" required>
                    <input type="date" name="fecha_nacimiento" id="pNacimiento" required>

                    <select name="sexo" id="pSexo" required>
                        <option value="">Sexo</option>
                        <option>Masculino</option>
                        <option>Femenino</option>
                    </select>

                    <input type="email" name="email" id="pCorreo" placeholder="Correo electrónico" required>
                    <input type="text" name="telefono" id="pTelefono" placeholder="Celular" required>

                    <select name="regimen" id="pRegimen" required>
                        <option value="">Régimen</option>
                        <option>Subsidiado</option>
                        <option>Contributivo</option>
                    </select>

                    <input type="text" name="eps" id="pEPS" placeholder="EPS" required>

                    <select name="tipo_sangre" id="pTipoSangre" required>
                        <option value="">Tipo de sangre</option>
                        <option>O+</option>
                        <option>O-</option>
                        <option>A+</option>
                        <option>A-</option>
                        <option>B+</option>
                        <option>B-</option>
                        <option>AB+</option>
                        <option>AB-</option>
                    </select>

                    <button type="submit" class="btn-primary">Guardar</button>
                </form>
            </div>
        </div>

        <div id="vistaInternados" class="vista">
            <div class="card">
                <h3>Pacientes Internados</h3>
                <div class="form-grid-2">
                    <input type="text" id="iDocumento" placeholder="Número de documento" required>
                    <input type="text" id="iMotivo" placeholder="Motivo de internación" required>
                    <input type="text" id="iSala" placeholder="Sala" required>
                    <input type="date" id="iFechaIngreso" required>
                    <button class="btn-primary" onclick="guardarInternado()">Guardar</button>
                </div>
            </div>
        </div>

        <div id="vistaAsignarCita" class="vista">
            <div class="card">
                <h3>Asignar Cita</h3>
                <div class="form-grid-2">
                    <input type="text" id="cDocumento" placeholder="Documento del paciente">
                    <input type="text" id="cNombre" placeholder="Nombre y Apellidos">
                    <select id="cEspecialidad" onchange="cargarMedicosDisponibles()">
                        <option value="">Especialidad</option>
                        <option>Medicina General</option>
                        <option>Pediatría</option>
                        <option>Odontología</option>
                    </select>
                    <select id="cMedico">
                        <option value="">Seleccione el médico</option>
                    </select>
                    <input type="date" id="cFecha">
                    <input type="time" id="cHora">
                    <select id="cSede">
                        <option value="">Sede</option>
                        <option>Sede Norte</option>
                        <option>Sede Centro</option>
                        <option>Sede Sur</option>
                    </select>
                    <input type="text" id="cEPS" placeholder="EPS">
                    <button class="btn-primary" onclick="asignarCita()">Guardar Cita</button>
                </div>
            </div>
        </div>

        <div id="vistaVerCitas" class="vista">
            <div class="card">
                <h3>Ver Citas</h3>
                <div class="form-grid-2">
                    <input type="text" id="buscarCitas" placeholder="Buscar por documento">
                    <button class="btn-primary" onclick="buscarCitas()">Buscar</button>
                </div>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Documento</th>
                            <th>Nombre</th>
                            <th>Especialidad</th>
                            <th>Médico</th>
                            <th>Fecha</th>
                            <th>Hora</th>
                            <th>Sede</th>
                            <th>EPS</th>
                        </tr>
                    </thead>
                    <tbody id="tablaVerCitas"></tbody>
                </table>
            </div>
        </div>

        <div id="vistaMedicos" class="vista">
            <div class="card">
                <h3>Médicos Registrados</h3>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Nombre y Apellidos</th>
                            <th>Especialidad</th>
                            <th>Disponibilidad</th>
                        </tr>
                    </thead>
                    <tbody id="tablaMedicos">
                    </tbody>
                </table>
            </div>
        </div>

        <div id="vistaHistoria" class="vista">
            <div class="card">
                <h3>Historia Clínica</h3>
                <div class="form-grid-2">
                    <input type="text" id="hcDocumento" placeholder="Documento del paciente">
                    <input type="date" id="hcFecha">
                    <button class="btn-primary" onclick="buscarHistoria()">Buscar</button>
                </div>

                <div id="resultadosHistoria" class="historia-visual">
                    <div
                        style="display:flex; justify-content: space-between; align-items: center; padding: 10px; border: 1px solid #ccc; border-radius: 5px; margin-top: 15px; background-color: #f9f9f9;">
                        <span style="font-weight: bold;">Nombre Apellidos</span>
                        <button class="btn-primary">
                            &#8681; Descargar Historia Clínica
                        </button>
                    </div>
                </div>
            </div>
        </div>

    </div>

    <script>
        function mostrarVista(id) {
            document.querySelectorAll('.vista').forEach(v => v.classList.remove('active'));
            document.getElementById(id).classList.add('active');

            const botones = document.querySelectorAll('.sidebar ul li');
            botones.forEach(b => b.classList.remove('active'));

            switch (id) {
                case "vistaRegistrarPaciente": botones[0].classList.add("active"); break;
                case "vistaInternados": botones[1].classList.add("active"); break;
                case "vistaAsignarCita": botones[2].classList.add("active"); break;
                case "vistaVerCitas": botones[3].classList.add("active"); break;
                case "vistaMedicos": botones[4].classList.add("active"); break;
                case "vistaHistoria": botones[5].classList.add("active"); break;
            }
        }
    </script>

    <script type="module" src="/javascript/admisionista.js"></script>

</body>

</html>
EOF
```

##### 10.4 frontend/html/index.html.
```bash
cat <<'EOF' > frontend/html/index.html
<!DOCTYPE html>
<html lang="es">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Login</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" defer></script>
  <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/toastify-js" defer></script>
  <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.css" />
  <link rel="stylesheet" href="/css/index.css" />
  <link rel="icon" type="image/png" href="/img/logo.png" />
</head>

<body class="d-flex justify-content-center align-items-center min-vh-100" style="background: #121212">
  <div class="wrapper shadow-lg p-4 rounded-4 text-white">
    <form id="login-form" class="form active">
      <h2 class="text-center mb-3">INICIO DE SESIÓN</h2>
      <div class="text-center mb-3">
        <img src="/img/logo.png" alt="Logo" class="logo" />
      </div>

      <div class="mb-3 position-relative">
        <span class="icon"><ion-icon name="person"></ion-icon></span>
        <input type="email" id="correo-login" name="correo" class="form-control bg-dark text-white border-secondary"
          placeholder="Correo" required />
      </div>

      <div class="mb-3 position-relative">
        <span class="icon"><ion-icon name="lock-closed"></ion-icon></span>
        <input type="password" id="contrasena-login" name="contrasena"
          class="form-control bg-dark text-white border-secondary" placeholder="Contraseña" required />
        <span class="eye-icon"><ion-icon name="eye-outline"></ion-icon></span>
      </div>

      <div class="text-end mb-3">
        <a href="#" class="text-info text-decoration-none small">¿Olvidaste tu contraseña?</a>
      </div>

      <button type="submit" class="btn btn-info w-100 mb-2">
        INICIAR SESIÓN
      </button>
    </form>
  </div>

  <script type="module" src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.esm.js"></script>
  <script nomodule src="https://unpkg.com/ionicons@7.1.0/dist/ionicons/ionicons.js"></script>

  <script type="module" src="/javascript/index.js"></script>
</body>

</html>
EOF
```

##### 10.5 frontend/javascript/admisionista.js.
```bash
cat <<'EOF' > frontend/javascript/admisionista.js
import { showmessaje } from './showmessaje.js';
import { API } from './api.js';

const $ = id => document.getElementById(id);

const sanitizeInput = str => typeof str === 'string' ? str.replace(/[<>"'`;(){}|\\]/g, '').trim() : '';
const escapeForHtml = s => typeof s === 'string' ? s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;') : '';

const isValidEmail = email => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
const isValidPassword = pwd => typeof pwd === 'string' && pwd.length >= 8 && /[A-Za-z]/.test(pwd) && /\d/.test(pwd);

const getFormData = form => Object.fromEntries([...new FormData(form)].map(([k, v]) => [k, sanitizeInput(v)]));

const handleRegistroPaciente = async e => {
  e.preventDefault();

  const token = localStorage.getItem('jwt');
  if (!token) return showmessaje('Debe iniciar sesión', 'error');

  const data = getFormData(e.target);

  const requiredFields = ['nombre','apellido','email','password','documento_id','fecha_nacimiento','sexo','regimen','eps','tipo_sangre'];
  for (let field of requiredFields) {
    if (!data[field]) return showmessaje(`El campo ${field} es obligatorio`, 'error');
  }

  if (!isValidEmail(data.email)) return showmessaje('Correo inválido', 'error');
  if (!isValidPassword(data.password)) return showmessaje('Contraseña inválida (mínimo 8 caracteres, letras y números)', 'error');

  const payload = {
    user: {
      nombre: data.nombre,
      apellido: data.apellido,
      email: data.email,
      password: data.password,
      rol: 'paciente'
    },
    paciente: {
      documento_id: data.documento_id,
      tipo_documento: data.tipo_documento || '',
      fecha_nacimiento: data.fecha_nacimiento,
      sexo: data.sexo,
      telefono: data.telefono || '',
      regimen: data.regimen,
      eps: data.eps,
      tipo_sangre: data.tipo_sangre
    }
  };

  try {
    const API_URL = 'https://apiclinica.derwincode.com/api/v1/auth/register_paciente';
    const res = await API.sendRequest(API_URL, payload, 'POST', { Authorization: `Bearer ${token}` });

    if (res?.status === 'success') {
      showmessaje(escapeForHtml(res.message), 'success');
      e.target.reset();
    } else {
      showmessaje(escapeForHtml(res?.message || 'Error al registrar paciente'), 'error');
    }
  } catch (err) {
    showmessaje(escapeForHtml('Error de conexión: ' + (err.message || 'desconocido')), 'error');
  }
};

const registroForm = $('registro-form');
if (registroForm) registroForm.addEventListener('submit', handleRegistroPaciente);
EOF
```

##### 10.6 frontend/javascript/api.js.
```bash
cat <<'EOF' > frontend/javascript/api.js
export class API {
    static async sendRequest(url, data = {}, method = 'POST') {
        try {
            const opts = {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + localStorage.getItem('jwt')
                }
            };

            if (method !== 'GET') opts.body = JSON.stringify(data);

            const res = await fetch(url, opts);
            const json = await res.json();

            if (!res.ok) return { status: 'error', message: json.message || `HTTP ${res.status}`};

            return json;
        } catch (err) {
            return { status: 'error', message: err.message };
        }
    }
}
EOF
```

##### 10.7 frontend/javascript/index.js.
```bash
cat <<'EOF' > frontend/javascript/index.js
import { showmessaje } from './showmessaje.js';
import { API } from './api.js';

const $ = id => document.getElementById(id);

const sanitizeInput = str => {
  if (typeof str !== 'string') return '';
  return str
    .replace(/[<>"'`;(){}|\\]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
};

const escapeForHtml = s => {
  if (typeof s !== 'string') return '';
  return s
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
};

const getFormData = f =>
  Object.fromEntries([...new FormData(f)].map(([k, v]) => [k, sanitizeInput(v)]));

const isValidEmail = email => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
const isValidPassword = pwd =>
  typeof pwd === 'string' && pwd.length >= 8 && /[A-Za-z]/.test(pwd) && /\d/.test(pwd);

document.addEventListener('click', e => {
  const icon = e.target.closest('.eye-icon');
  if (!icon) return;
  const input = icon.previousElementSibling;
  const eye = icon.querySelector('ion-icon');
  const visible = input.type === 'text';
  input.type = visible ? 'password' : 'text';
  eye.name = visible ? 'eye-outline' : 'eye-off-outline';
});

const handleLogin = async e => {
  e.preventDefault();
  const data = getFormData(e.target);

  if (!data.correo || !data.contrasena)
    return showmessaje('Completa todos los campos', 'error');

  if (!isValidEmail(data.correo))
    return showmessaje('Correo inválido', 'error');

  if (!isValidPassword(data.contrasena))
    return showmessaje('Contraseña inválida (mínimo 8 caracteres, usa letras y números)', 'error');

  try {
    const API_URL = 'https://apiclinica.derwincode.com/api/v1/auth/login';
    const payload = {
      email: data.correo,
      password: data.contrasena
    };
    const res = await API.sendRequest(API_URL, payload, 'POST');

    if (res?.status === 'success') {
      if (res.token) localStorage.setItem('jwt', res.token);

      if (res.rol) {
        const rolFile = res.rol.toLowerCase() + '.html';
        showmessaje(escapeForHtml('Inicio de sesión exitoso'), 'success');
        setTimeout(() => { window.location.href = '/' + rolFile; }, 800);
      }
    } else {
      const msg = res?.message ? escapeForHtml(String(res.message)) : 'No se pudo iniciar su sesión';
      showmessaje(msg, 'error');
    }
  } catch (err) {
    showmessaje(escapeForHtml('Error de conexión: ' + (err.message || 'desconocido')), 'error');
  }
};

$('login-form').addEventListener('submit', handleLogin);
EOF
```

##### 10.8 frontend/javascript/showmessaje.js.
```bash
cat <<'EOF' > frontend/javascript/showmessaje.js
export function showmessaje(message, type) {
    Toastify({
        text: message,
        duration: 3000,
        gravity: "bottom",
        position: "left",
        stopOnFocus: true,
        style: {
            background: type === "success" ? "green" : "red"
        },
        onclick: function () { }
    }).showToast();
}
EOF
```

#### Configurar Kubernetes para Citus.
##### 11.1 archivo k8s/backend-deployment.yaml.
```bash
cat <<EOF > k8s/backend-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: $K8S_NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
        - name: backend
          image: $BACKEND_IMAGE
          env:
            - name: DATABASE_URL
              value: postgresql://$DB_USER:$DB_PASSWORD@$COORDINATOR_HOST:5432/$DB_NAME
          ports:
            - containerPort: $BACKEND_PORT
EOF
```

##### 11.2 Archivo k8s/backend-service.yaml.
```bash
cat <<EOF > k8s/backend-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: backend-service
  namespace: $K8S_NAMESPACE
spec:
  type: NodePort
  selector:
    app: backend
  ports:
    - port: $BACKEND_PORT
      targetPort: $BACKEND_PORT
      nodePort: $BACKEND_NODEPORT
EOF
```

##### 11.3 Archivo k8s/citus/citus-coordinator-service.yaml.
```bash
cat <<EOF > k8s/citus/citus-coordinator-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: citus-coordinator
  namespace: $K8S_NAMESPACE
spec:
  clusterIP: None
  selector:
    app: citus-coordinator
  ports:
    - port: 5432
      name: postgres
EOF
```

##### 11.4 Archivo k8s/citus/citus-coordinator-statefulset.yaml.
```bash
cat <<EOF > k8s/citus/citus-coordinator-statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: citus-coordinator
  namespace: $K8S_NAMESPACE
spec:
  serviceName: citus-coordinator
  replicas: 1
  selector:
    matchLabels:
      app: citus-coordinator
  template:
    metadata:
      labels:
        app: citus-coordinator
    spec:
      containers:
        - name: coordinator
          image: citusdata/citus:12.1
          ports:
            - containerPort: 5432
          env:
            - name: POSTGRES_USER
              value: $DB_USER
            - name: POSTGRES_PASSWORD
              value: $DB_PASSWORD
            - name: POSTGRES_DB
              value: $DB_NAME
            - name: CITUS_COORDINATOR
              value: "true"
          volumeMounts:
            - name: coordinator-storage
              mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
    - metadata:
        name: coordinator-storage
      spec:
        accessModes: [ "ReadWriteOnce" ]
        resources:
          requests:
            storage: 2Gi
EOF
```

##### 11.5 Archivo k8s/citus/citus-worker-service.yaml.
```bash
cat <<EOF > k8s/citus/citus-worker-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: citus-worker
  namespace: $K8S_NAMESPACE
spec:
  clusterIP: None
  selector:
    app: citus-worker
  ports:
    - port: 5432
      name: postgres
EOF
```

##### 11.6 Archivo k8s/citus/citus-worker-statefulset.yaml.
```bash
cat <<EOF > k8s/citus/citus-worker-statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: citus-worker
  namespace: $K8S_NAMESPACE
spec:
  serviceName: citus-worker
  replicas: 2
  selector:
    matchLabels:
      app: citus-worker
  template:
    metadata:
      labels:
        app: citus-worker
    spec:
      containers:
        - name: worker
          image: citusdata/citus:12.1
          ports:
            - containerPort: 5432
          env:
            - name: POSTGRES_USER
              value: $DB_USER
            - name: POSTGRES_PASSWORD
              value: $DB_PASSWORD
            - name: POSTGRES_DB
              value: $DB_NAME
          volumeMounts:
            - name: worker-storage
              mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
    - metadata:
        name: worker-storage
      spec:
        accessModes: [ "ReadWriteOnce" ]
        resources:
          requests:
            storage: 1Gi
EOF
```

#### Configurar nginx.
##### 12.1 Dar permisos correctos al proyecto.
```bash
sudo chown -R $(whoami):www-data "$PROJECT_DIR"
sudo find "$PROJECT_DIR" -type d -exec chmod 755 {} \;
sudo find "$PROJECT_DIR" -type f -exec chmod 644 {} \;
sudo chmod o+x "$HOME" "$(xdg-user-dir DOCUMENTS)" "$PROJECT_DIR"
```

##### 12.2 Añadir el contenido de sites-available
```bash
sudo tee /etc/nginx/sites-available/$PROJECT_NAME > /dev/null <<EOF
server {
    listen 127.0.0.1:8085;
    server_name $PROJECT_NAME;
    root $WEB_ROOT;
    index index.html;

    gzip on;
    gzip_types text/plain text/css application/javascript application/json image/svg+xml;
    gzip_min_length 256;

    location /css/ {
        root $STATIC_DIR;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        add_header Pragma "no-cache";
        add_header Expires 0;
        expires off;
        try_files \$uri =404;
        access_log off;
    }

    location /javascript/ {
        root $STATIC_DIR;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        add_header Pragma "no-cache";
        add_header Expires 0;
        expires off;
        try_files \$uri =404;
        access_log off;
    }

    location /img/ {
        root $STATIC_DIR;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        add_header Pragma "no-cache";
        add_header Expires 0;
        expires off;
        try_files \$uri =404;
        access_log off;
    }

    location = /index.html { return 301 /; }
    location ~* \.html?$ { try_files \$uri =404; }
    location = / { try_files /index.html =404; }
    location ~ /\. { deny all; access_log off; log_not_found off; }
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header Referrer-Policy "no-referrer-when-downgrade";
}
EOF
```

##### 12.3 Activar la configuración.
```bash
sudo ln -sf /etc/nginx/sites-available/$PROJECT_NAME /etc/nginx/sites-enabled/$PROJECT_NAME
sudo nginx -t
sudo systemctl restart nginx
```

#### 13. Instalar Kubernetes CLI y Minikube.
```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
```

#### 14. Crear y activar el entorno virtual de Python.
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 15. Iniciar Minikube y crear namespace.
```bash
minikube start --driver=docker
kubectl create namespace $K8S_NAMESPACE
```

#### 16. Iniciar clinica-secrets.
```bash
kubectl create secret generic clinica-secrets -n $K8S_NAMESPACE --from-literal=DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@$COORDINATOR_HOST:5432/$DB_NAME"
```

#### 17. Configurar middleware
```bash
kubectl apply -f backend/app/middleware/middleware-deployment.yaml -n $K8S_NAMESPACE
```

#### 18. Aplicar configuración de Citus.
```bash
kubectl apply -f k8s/citus -n $K8S_NAMESPACE
```

*Nota: Espera al menos 30 segundos antes de continuar para asegurar que los pods del coordinador y los workers estén totalmente inicializados y listos para conexiones.*

#### 19. Configurar nodos y crear tablas distribuidas.
```bash
kubectl exec -n $K8S_NAMESPACE -i citus-coordinator-0 -- psql -U $DB_USER -d $DB_NAME <<EOF
SELECT * FROM master_add_node('citus-worker-0.citus-worker.$K8S_NAMESPACE.svc.cluster.local', 5432);
SELECT * FROM master_add_node('citus-worker-1.citus-worker.$K8S_NAMESPACE.svc.cluster.local', 5432);

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TABLE IF EXISTS usuario CASCADE;
CREATE TABLE usuario (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    nombre VARCHAR(100) NOT NULL,
    apellido VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    hash_password TEXT NOT NULL,
    rol VARCHAR(20) NOT NULL CHECK (rol IN ('paciente','medico','admisionista')),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
SELECT create_reference_table('usuario');

DROP TABLE IF EXISTS paciente CASCADE;
CREATE TABLE paciente (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tipo_documento VARCHAR(20),
    documento_id VARCHAR(30) NOT NULL,
    fecha_nacimiento DATE NOT NULL,
    sexo VARCHAR(15),
    telefono VARCHAR(30),
    regimen VARCHAR(50),
    eps VARCHAR(100),
    tipo_sangre VARCHAR(10),
    usuario_id UUID NOT NULL REFERENCES usuario(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
SELECT create_distributed_table('paciente', 'id');
EOF
```

#### 20. Construir imagen del backend y cargar en Minikube.
```bash
docker build -t $BACKEND_IMAGE backend/
minikube image load $BACKEND_IMAGE
```

#### 21. Verificar pods y nodos activos.
```bash
kubectl get pods,svc -n $K8S_NAMESPACE -o wide
kubectl exec -n $K8S_NAMESPACE -it citus-coordinator-0 -- psql -U $DB_USER -d $DB_NAME -c "SELECT * FROM citus_get_active_worker_nodes();"
```

##### 22. Aplicar configuración.
```bash
kubectl apply -f k8s/backend-deployment.yaml -n $K8S_NAMESPACE
kubectl apply -f k8s/backend-service.yaml -n $K8S_NAMESPACE
```

*Nota: Espera unos 30 segundos antes de continuar. Esto garantiza que los pods del backend estén completamente desplegados y listos para recibir tráfico.*

#### 23. Probar el backend desde el clúster.
```bash
kubectl get pods -n $K8S_NAMESPACE
kubectl logs -n $K8S_NAMESPACE deployment/backend
minikube service backend-service -n $K8S_NAMESPACE --url
```
