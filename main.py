import uvicorn 
from jose import JWTError, jwt
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, PydanticUserError, create_model
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer
from typing import List
from datetime import timedelta
from datetime import datetime
from typing import Optional
from fastapi_spotilike_main import crud, database
from fastapi_spotilike_main import models
from decouple import config


app = FastAPI(title="FastAPI Spotilike",
    description="API for Spotilike application",
    version="1.0.0",
    arbitrary_types_allowed=True)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Clé secrète pour signer le token (à remplacer par votre propre clé secrète)
#secret = "ea504dfd74cdc3fbddcb4e67c73b6070"
#ALGORITHM = "HS256"
API_KEY = config('secret')
ALGO = config('ALGORITHM')
try:

    class Model(BaseModel):
        x: 43 = 123

except PydanticUserError as exc_info:
    assert exc_info.code == 'schema-for-unknown-type'
def generate_token(data: dict):
    # Calcul de la date d'expiration du token
    expire = datetime.utcnow() + timedelta(minutes=15)
    
    # Création des claims (payload) du token
    to_encode = {**data, "exp": expire}
    
    # Génération du token JWT
    encoded_jwt = jwt.encode(to_encode, API_KEY, algorithm=ALGO)
    
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, "ea504dfd74cdc3fbddcb4e67c73b6070", algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    return username

# Fonction pour authentifier l'utilisateur
def authenticate_user(username: str, password: str):
    # Remplacez cela par votre logique d'authentification réelle
    # Par exemple, vérification dans une base de données, comparaison de mots de passe, etc.
    if username == "user" and password == "password":
        return {"username": username, "email": "user@example.com"}
    else:
        return None


def delete_artist(db: Session, artist_id: int):
    # 1. Obtenir l'artiste à supprimer
    artist = db.query(models.Artiste).filter(models.Artiste.id == artist_id).first()

    if artist:
        # 2. Supprimer les albums associés
        db.query(models.Album).filter(models.Album.artiste == artist_id).delete(synchronize_session=False)

        # 3. Supprimer les morceaux associés
        db.query(models.Morceau).filter(models.Morceau.artiste == artist_id).delete(synchronize_session=False)

        # 4. Effectuer la suppression de l'artiste
        db.delete(artist)
        db.commit()
        return artist
    else:
        return None

# Dependency to get the database session
def get_db(username: str, password: str):
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()
        # Route pour la connexion de l'utilisateur


def create_jwt_token(data: dict):
    to_encode = data.copy()
    # Ajoutez des informations supplémentaires au token si nécessaire
    # par exemple, la durée de validité (expires_delta)
    encoded_jwt = jwt.encode(to_encode, API_KEY, algorithm=ALGO)
    return encoded_jwt

def authenticate_user(db: Session, username: str, password: str):
    user = crud.get_user_by_username(db, username)
    if user and verify_password(password, user.password):
        return user

# La fonction pour générer un token JWT
def create_jwt_token(data: dict):
    to_encode = data.copy()
    # Ajoutez des informations supplémentaires au token si nécessaire
    # par exemple, la durée de validité (expires_delta)
    encoded_jwt = jwt.encode(to_encode, API_KEY, algorithm=ALGO)
    return encoded_jwt

def verify_password(plain_password, hashed_password):
    # Logique pour vérifier le mot de passe, par exemple en utilisant une bibliothèque de hachage
    # Assurez-vous d'utiliser une méthode de hachage sécurisée comme bcrypt
    # Renvoie True si le mot de passe correspond, sinon False
    pass

# Autre code...


    
    
# Modèle Pydantic pour le token
class Token(BaseModel):
    access_token: str
    token_type: str


# Modèles
class AlbumBase(BaseModel):
    titre: str
    pochette: str
    date_de_sortie: str

class AlbumCreate(AlbumBase):
    morceaux: List[int]
    artiste: int

class Album(BaseModel):
    titre: str
    pochette: str
    date_de_sortie: str
    morceaux: List[models.Morceau]
    artiste: models.Artiste
    model_config = ConfigDict(from_attributes=True)

class Morceau(BaseModel):
    titre: str
    duree: str
    artiste: int
    genre: List[str]
    album: int
    model_config = ConfigDict(arbitrary_types_allowed=True)

class Artiste(BaseModel):
    nom_artiste: str
    avatar: str
    biographie: str

class Genre(BaseModel):
    titre: str
    description: str

class Utilisateur(BaseModel):
    nom_utilisateur: str
    mot_de_passe: str
    email: str

# Endpoints

# 1. GET - /api/albums : Récupère la liste de tous les albums

@app.get("/api/albums", response_model=List[Album])
async def read_albums(db: Session = Depends(get_db)):
    return crud.read_albums(db)


# 2. GET - /api/albums/{id} : Récupère les détails de l’album précisé par {id}
@app.get("/api/albums/{album_id}", response_model=models.Album)
async def get_album(album_id: int, db: Session = Depends(get_db)):
    return crud.get_album(db, album_id)

# 3. GET - /api/albums/{id}/songs : Récupère les morceaux de l’album précisé par {id}
@app.get("/api/albums/{album_id}/songs", response_model=List[models.Morceau])
async def get_album_songs(album_id: int, db: Session = Depends(get_db)):
    return crud.get_album_songs(db, album_id)

# 4. GET - /api/genres : Récupère la liste de tous les genres
@app.get("/api/genres", response_model=List[models.Genre])
async def get_all_genres(db: Session = Depends(get_db)):
    return crud.get_genres(db)

# 5. GET - /api/artists/{id}/songs : Récupère la liste de tous les morceaux de l’artiste précisé par {id}
@app.get("/api/artists/{artist_id}/songs", response_model=List[models.Morceau])
async def get_artist_songs(artist_id: int, db: Session = Depends(get_db)):
    return crud.get_artist_songs(db, artist_id)

# 6. POST - /api/users/signin : Ajout d’un utilisateur
@app.post("/api/users/signin", response_model=models.Utilisateur)
async def create_user(user: models.Utilisateur, db: Session = Depends(get_db)):
    return crud.create_user(db, user)

# 7. POST - /api/users/login : Connexion d’un utilisateur (JWT)
@app.post("/api/users/login", response_model=Token)
async def user_login(form_data: OAuth2PasswordBearer = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nom d'utilisateur ou mot de passe incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Générez le token JWT avec les informations nécessaires
    token_data = {"sub": user.username, "scopes": []}
    token = create_jwt_token(token_data)

    # Retournez le token dans le modèle Token
    return Token(access_token=token, token_type="bearer")

# 8. POST - /api/albums : Ajout d’un album
@app.post("/api/albums", response_model=models.Album)
async def create_album(album: models.Album, db: Session = Depends(get_db)):
    return crud.create_album(db, album)

# 9. POST - /api/albums/{id}/songs : Ajout d’un morceau dans l’album précisé par {id}
@app.post("/api/albums/{album_id}/songs", response_model=models.Morceau)
async def add_song_to_album(album_id: int, morceau: models.Morceau, db: Session = Depends(get_db)):
    return crud.add_song_to_album(db, album_id, morceau)

# 10. PUT - /api/artists/{id} : Modification de l’artiste précisé par {id}
@app.put("/api/artists/{artist_id}", response_model=models.Artiste)
async def update_artist(artist_id: int, artiste: models.Artiste, db: Session = Depends(get_db)):
    return crud.update_artist(db, artist_id, artiste)

# 11. PUT - /api/albums/{id} : Modification de l’album précisé par {id}
@app.put("/api/albums/{album_id}", response_model=models.Album)
async def update_album(album_id: int, album: models.Album, db: Session = Depends(get_db)):
    return crud.update_album(db, album_id, album)

# 12. PUT - /api/genres/{id} : Modification du genre précisé par {id}
@app.put("/api/genres/{genre_id}")
async def update_genre(genre_id: int, genre: models.Genre, db: Session = Depends(get_db)):
    return crud.update_genre(db, genre_id, genre)


# 13. DELETE - /api/users/{id} : Suppression de l'utilisateur précisé par {id}
@app.delete("/api/users/{user_id}", response_model=models.Utilisateur)
async def delete_user(user_id: int, current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = crud.delete_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    
    # Aucune donnée n'est renvoyée, le statut HTTP 204 est approprié
    return None

# 14. DELETE - /api/albums/{id} : Suppression de l'album précisé par {id}
@app.delete("/api/albums/{album_id}", response_model=models.Album)
async def delete_album(album_id: int, db: Session = Depends(get_db)):
    album = crud.delete_album(db, album_id)
    if album is None:
        raise HTTPException(status_code=404, detail="Album non trouvé")
    return album

# 15. DELETE - /api/artists/{id} : Suppression de l'artiste précisé par {id}
@app.delete("/api/artists/{artist_id}", response_model=models.Artiste)
async def delete_artist(artist_id: int, db: Session = Depends(get_db)):
    artist = crud.delete_artiste(db, artist_id)
    if artist is None:
        raise HTTPException(status_code=404, detail="Artiste non trouvé")
    return artist

# ...