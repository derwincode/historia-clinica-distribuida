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
#### 9.1 Crear archivo _init_.py
```bash
touch backend/app/__init__.py
```

##### 9.2 Archivo backend/app/api/v1/endpoints/auth.py.
```bash
cat <<EOF > backend/app/api/v1/endpoints/auth.py
from fastapi import APIRouter, HTTPException, status
from app.schemas.auth import UserCreate, UserOut, TokenResponse
from app.services.auth_service import create_user, authenticate_and_create_token
from pydantic import ValidationError

router = APIRouter()

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate):
    try:
        created = create_user(user)
    except ValueError as e:
        if str(e) == "email_exists":
            raise HTTPException(status_code=400, detail="El correo ya está registrado")
        raise HTTPException(status_code=500, detail="Error al crear usuario")
    # create token
    auth = authenticate_and_create_token(user.email, user.password)
    if not auth:
        raise HTTPException(status_code=500, detail="Usuario creado pero no se pudo generar token")
    return {"access_token": auth["access_token"], "token_type": "bearer"}


@router.post("/login", response_model=TokenResponse)
def login(form_data: UserCreate):
    # Reuse authentication helper (we accept email + password in same UserCreate shape for simplicity)
    auth = authenticate_and_create_token(form_data.email, form_data.password)
    if not auth:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    return {"access_token": auth["access_token"], "token_type": "bearer"}
EOF
```

##### 9.3 Archivo backend/app/core/security.py.
```bash
cat <<EOF > backend/app/core/security.py
import os
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt

PWD_CTX = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "cambiame_ya")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))

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
EOF
```

##### 9.4 Archivo backend/app/db/connection.py.
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
        with conn.cursor() as cur:
            cur.execute(query, params)
            conn.commit()
            try:
                return cur.fetchone()
            except Exception:
                return None
    except:
        conn.rollback()
        raise
    finally:
        conn.close()
EOF
```

##### 9.5 Archivo backend/app/main.py.
```bash
cat <<EOF > backend/app/main.py
from fastapi import FastAPI
import psycopg2
import os

app = FastAPI()
def db():
    return psycopg2.connect(os.getenv("DATABASE_URL"))

@app.get("/ping")
def ping():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT 1;")
    return {"pong": cur.fetchone()[0]}

from app.api.v1.endpoints import auth
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Autenticación"])
EOF
```

##### 9.6 Archivo backend/app/middleware/middleware-deployment.yaml.
```bash
cat <<EOF > backend/app/middleware/middleware-deployment.yaml
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
          image: middleware-citus:1.0
          ports:
            - containerPort: 8000
          envFrom:
            - secretRef:
                name: clinica-secrets
EOF
```

##### 9.7 Archivo backend/app/schemas/auth.py.
```bash
cat <<EOF > backend/app/schemas/auth.py
from pydantic import BaseModel, EmailStr, constr
from typing import Optional

class UserCreate(BaseModel):
    nombre: constr(min_length=1)
    apellido: constr(min_length=1)
    email: EmailStr
    password: constr(min_length=8)
    rol: constr(pattern="^(paciente|medico|admisionista|resultados)$")

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

##### 9.8 Archivo backend/app/services/auth_service.py.
```bash
cat <<EOF > backend/app/services/auth_service.py
from app.db.connection import query_one, execute
from app.core.security import get_password_hash, verify_password, create_access_token
import uuid

def get_user_by_email(email: str):
    q = "SELECT id, nombre, apellido, email, hash_password, rol, fecha_creacion FROM usuario WHERE email = %s"
    return query_one(q, (email,))

def create_user(user_in):
    # Check duplicate
    existing = get_user_by_email(user_in.email)
    if existing:
        raise ValueError("email_exists")

    hashed = get_password_hash(user_in.password)
    q = """
    INSERT INTO usuario (nombre, apellido, email, hash_password, rol)
    VALUES (%s, %s, %s, %s, %s)
    RETURNING id, nombre, apellido, email, rol, fecha_creacion
    """
    row = execute(q, (user_in.nombre, user_in.apellido, user_in.email, hashed, user_in.rol))
    # execute() returns None if DB cursor.fetchone() not available; so re-query the inserted user by email
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
EOF
```

##### 9.9 Dockerfile.
```bash
cat <<EOF > backend/Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE $BACKEND_PORT
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "$BACKEND_PORT"]
EOF
```

##### 9.10 Dependencias.
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
EOF
```

#### Configurar Kubernetes para Citus.
##### 10.1 archivo k8s/backend-deployment.yaml.
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

##### 10.2 Archivo k8s/backend-service.yaml.
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

##### 10.3 Archivo k8s/citus/citus-coordinator-service.yaml.
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

##### 10.4 Archivo k8s/citus/citus-coordinator-statefulset.yaml.
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

##### 10.5 Archivo k8s/citus/citus-worker-service.yaml.
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

##### 10.6 Archivo k8s/citus/citus-worker-statefulset.yaml.
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
##### 11.1 Dar permisos correctos al proyecto.
```bash
sudo chown -R $(whoami):www-data "$PROJECT_DIR"
sudo find "$PROJECT_DIR" -type d -exec chmod 755 {} \;
sudo find "$PROJECT_DIR" -type f -exec chmod 644 {} \;
sudo chmod o+x "$HOME" "$(xdg-user-dir DOCUMENTS)" "$PROJECT_DIR"
```

##### 11.2 Añadir el contenido de sites-available
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

##### 11.3 Activar la configuración.
```bash
sudo ln -sf /etc/nginx/sites-available/$PROJECT_NAME /etc/nginx/sites-enabled/$PROJECT_NAME
sudo nginx -t
sudo systemctl restart nginx
```

#### 12. Instalar Kubernetes CLI y Minikube.
```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
```

#### 13. Crear y activar el entorno virtual de Python.
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 14. Iniciar Minikube y crear namespace.
```bash
minikube start --driver=docker
kubectl create namespace $K8S_NAMESPACE
```

#### 15. Configurar middleware
```bash
kubectl apply -f backend/app/middleware/middleware-deployment.yaml -n $K8S_NAMESPACE
```

#### 16. Aplicar configuración de Citus.
```bash
kubectl apply -f k8s/citus -n $K8S_NAMESPACE
```

*Nota: Espera al menos 30 segundos antes de continuar para asegurar que los pods del coordinador y los workers estén totalmente inicializados y listos para conexiones.*

#### 17. Configurar nodos y crear tablas distribuidas.
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
    rol VARCHAR(20) NOT NULL CHECK (rol IN ('paciente','medico','admisionista','resultados')),
    fecha_creacion TIMESTAMP NOT NULL DEFAULT NOW()
);
SELECT create_reference_table('usuario');

DROP TABLE IF EXISTS paciente CASCADE;
CREATE TABLE paciente (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    documento_id VARCHAR(30) UNIQUE NOT NULL,
    tipo_documento VARCHAR(20),
    fecha_nacimiento DATE NOT NULL,
    sexo VARCHAR(15),
    direccion TEXT,
    telefono VARCHAR(30),
    contacto_emergencia VARCHAR(150),
    alergias TEXT,
    medicamentos_actuales TEXT,
    usuario_id UUID NOT NULL REFERENCES usuario(id)
);
SELECT create_distributed_table('paciente', 'id');

DROP TABLE IF EXISTS admision CASCADE;
CREATE TABLE admision (
    id UUID DEFAULT uuid_generate_v4(),
    paciente_id UUID NOT NULL,
    fecha_admision TIMESTAMP NOT NULL DEFAULT NOW(),
    motivo TEXT,
    estado VARCHAR(20) CHECK (estado IN ('abierta','cerrada')),
    triage VARCHAR(20),
    notas_ingreso TEXT
);
SELECT create_distributed_table('admision', 'paciente_id');

DROP TABLE IF EXISTS medico_consulta CASCADE;
CREATE TABLE medico_consulta (
    id UUID DEFAULT uuid_generate_v4(),
    admision_id UUID,
    paciente_id UUID NOT NULL,
    medico_id UUID NOT NULL,
    fecha TIMESTAMP NOT NULL DEFAULT NOW(),
    sintomas TEXT,
    signos_vitales JSONB,
    diagnostico TEXT,
    plan_tratamiento TEXT
);
ALTER TABLE medico_consulta 
  ADD CONSTRAINT fk_medico_usuario FOREIGN KEY (medico_id) REFERENCES usuario(id);
SELECT create_distributed_table('medico_consulta', 'paciente_id');

DROP TABLE IF EXISTS orden_medica CASCADE;
CREATE TABLE orden_medica (
    id UUID DEFAULT uuid_generate_v4(),
    paciente_id UUID NOT NULL,
    admision_id UUID,
    medico_id UUID,
    fecha TIMESTAMP NOT NULL DEFAULT NOW(),
    tipo VARCHAR(50),
    detalle TEXT
);
ALTER TABLE orden_medica 
  ADD CONSTRAINT fk_orden_medico_usuario FOREIGN KEY (medico_id) REFERENCES usuario(id);
SELECT create_distributed_table('orden_medica', 'paciente_id');

DROP TABLE IF EXISTS resultados_laboratorio CASCADE;
CREATE TABLE resultados_laboratorio (
    id UUID DEFAULT uuid_generate_v4(),
    paciente_id UUID NOT NULL,
    admision_id UUID,
    tipo_examen VARCHAR(100) NOT NULL,
    fecha TIMESTAMP NOT NULL DEFAULT NOW(),
    resultado TEXT,
    responsable_id UUID
);
ALTER TABLE resultados_laboratorio 
  ADD CONSTRAINT fk_resultados_responsable FOREIGN KEY (responsable_id) REFERENCES usuario(id);
SELECT create_distributed_table('resultados_laboratorio', 'paciente_id');

DROP TABLE IF EXISTS historia_clinica_pdf CASCADE;
CREATE TABLE historia_clinica_pdf (
    id UUID DEFAULT uuid_generate_v4(),
    paciente_id UUID NOT NULL,
    admision_id UUID,
    nombre_archivo TEXT NOT NULL,
    contenido BYTEA NOT NULL,
    fecha_subida TIMESTAMP NOT NULL DEFAULT NOW(),
    generado_por UUID
);
ALTER TABLE historia_clinica_pdf 
  ADD CONSTRAINT fk_historia_generado_por FOREIGN KEY (generado_por) REFERENCES usuario(id);
SELECT create_distributed_table('historia_clinica_pdf', 'paciente_id');

DROP TABLE IF EXISTS token_auditoria CASCADE;
CREATE TABLE token_auditoria (
    id UUID DEFAULT uuid_generate_v4(),
    usuario_id UUID NOT NULL,
    accion TEXT NOT NULL,
    ip VARCHAR(50),
    timestamp TIMESTAMP NOT NULL DEFAULT NOW()
);
ALTER TABLE token_auditoria 
  ADD CONSTRAINT fk_auditoria_usuario FOREIGN KEY (usuario_id) REFERENCES usuario(id);
SELECT create_reference_table('token_auditoria');
EOF
```

#### 18. Verificar pods y nodos activos.
```bash
kubectl get pods,svc -n $K8S_NAMESPACE -o wide
kubectl exec -n $K8S_NAMESPACE -it citus-coordinator-0 -- psql -U $DB_USER -d $DB_NAME -c "SELECT * FROM citus_get_active_worker_nodes();"
```

#### 19. Construir imagen del backend y cargar en Minikube.
```bash
docker build -t $BACKEND_IMAGE backend/
minikube image load $BACKEND_IMAGE
```

##### 20 Aplicar configuración.
```bash
kubectl apply -f k8s/backend-deployment.yaml -n $K8S_NAMESPACE
kubectl apply -f k8s/backend-service.yaml -n $K8S_NAMESPACE
```

*Nota: Espera unos 30 segundos antes de continuar. Esto garantiza que los pods del backend estén completamente desplegados y listos para recibir tráfico.*

#### 21. Probar el backend desde el clúster.
```bash
kubectl get pods -n $K8S_NAMESPACE
kubectl logs -n $K8S_NAMESPACE deployment/backend
minikube service backend-service -n $K8S_NAMESPACE --url
```
