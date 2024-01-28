from sqlalchemy.orm import Session
from . import models

# Opérations CRUD pour la table "Album"
def get_albums(db: Session):
    return db.query(models.Album).all()

def get_album(db: Session, album_id: int):
    return db.query(models.Album).filter(models.Album.id == album_id).first()

def create_album(db: Session, album: models.Album):
    db_album = models.Album(**album.dict())
    db.add(db_album)
    db.commit()
    db.refresh(db_album)
    return db_album

def update_album(db: Session, album_id: int, updated_album: models.Album):
    db_album = db.query(models.Album).filter(models.Album.id == album_id).first()
    if db_album:
        for key, value in updated_album.dict().items():
            setattr(db_album, key, value)
        db.commit()
        db.refresh(db_album)
    return db_album

def delete_album(db: Session, album_id: int):
    db_album = db.query(models.Album).filter(models.Album.id == album_id).first()
    if db_album:
        db.delete(db_album)
        db.commit()
    return db_album

# Ajoutez des opérations CRUD similaires pour les autres tables (Morceau, Artiste, Genre, Utilisateur) selon vos besoins

# Opérations CRUD pour la table "Morceau"
def get_morceaux(db: Session):
    return db.query(models.Morceau).all()

def get_morceau(db: Session, morceau_id: int):
    return db.query(models.Morceau).filter(models.Morceau.id == morceau_id).first()

# ...

# Opérations CRUD pour la table "Artiste"
def get_artistes(db: Session):
    return db.query(models.Artiste).all()

def get_artiste(db: Session, artiste_id: int):
    return db.query(models.Artiste).filter(models.Artiste.id == artiste_id).first()

# ...

# Opérations CRUD pour la table "Genre"
def get_genres(db: Session):
    return db.query(models.Genre).all()

def get_genre(db: Session, genre_id: int):
    return db.query(models.Genre).filter(models.Genre.id == genre_id).first()

# ...

# Opérations CRUD pour la table "Utilisateur"
def get_utilisateurs(db: Session):
    return db.query(models.Utilisateur).all()

def get_utilisateur(db: Session, utilisateur_id: int):
    return db.query(models.Utilisateur).filter(models.Utilisateur.id == utilisateur_id).first()

# ...
