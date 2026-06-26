import os
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from core.security import verify_password, create_access_token, get_password_hash
from core.config import get_settings
from pydantic import BaseModel

router = APIRouter()
settings = get_settings()

# Stub de autenticação para desenvolvimento (em produção, usar um banco de usuários real).
# ATENÇÃO: nenhuma senha deve ser versionada. A senha do admin de desenvolvimento é lida
# da variável de ambiente SENTINEL_DEV_ADMIN_PASSWORD; se não definida, o login fica inativo.
# Ver docs/PLANO_MELHORIA_HANDOFF.md (Fase 0 / segurança).
_dev_admin_password = os.getenv("SENTINEL_DEV_ADMIN_PASSWORD", "")
FAKE_USERS_DB = {
    "admin": {
        "username": "admin",
        "full_name": "Administrador",
        "hashed_password": get_password_hash(_dev_admin_password) if _dev_admin_password else "",
    },
}

class Token(BaseModel):
    access_token: str
    token_type: str
    username: str

@router.post("/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = FAKE_USERS_DB.get(form_data.username)
    if not user or not user["hashed_password"] or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "username": user["username"]
    }
