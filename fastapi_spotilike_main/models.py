
from sqlalchemy import Column, Integer, String, ForeignKey, Table
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from pydantic import ConfigDict

Base = declarative_base()

# Table de liaison entre Artiste et Morceau (many-to-many)
artist_morceau_association = Table(
    'artist_morceau_association',
    Base.metadata,
    Column('artiste_id', Integer, ForeignKey('artistes.id')),
    Column('morceau_id', Integer, ForeignKey('morceaux.id'))
)

class Album(Base):
    __tablename__ = "albums"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    cover = Column(String)  # Pochette
    release_date = Column(String)  # Date_de_sortie

    # Relation avec d'autres tables
    artist_id = Column(Integer, ForeignKey("artistes.id"))
    artist = relationship("Artiste", back_populates="albums")

    # Relation avec la table de liaison Morceau
    songs = relationship("Morceau", back_populates="album")

class Morceau(Base):
    __tablename__ = "morceaux"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    duration = Column(String)  # Duree

    # Relation avec d'autres tables
    artist_id = Column(Integer, ForeignKey("artistes.id"))
    artist = relationship("Artiste", back_populates="songs")

    album_id = Column(Integer, ForeignKey("albums.id"))
    album = relationship("Album", back_populates="songs")

    # Relation many-to-many avec la table Artistes
    artistes = relationship("Artiste", secondary=artist_morceau_association, back_populates="morceaux")
    model_config = ConfigDict(arbitrary_types_allowed=True)
class Artiste(Base):
    __tablename__ = "artistes"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)  # Nom_artiste
    avatar = Column(String)
    biography = Column(String)  # Biographie

    # Relation avec d'autres tables
    albums = relationship("Album", back_populates="artist")
    songs = relationship("Morceau", back_populates="artist")

class Genre(Base):
    __tablename__ = "genres"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)  # Description

    # Relation avec d'autres tables
    albums = relationship("Album", secondary="album_genre_association", back_populates="genres")

# Table de liaison entre Album et Genre (many-to-many)
album_genre_association = Table(
    'album_genre_association',
    Base.metadata,
    Column('album_id', Integer, ForeignKey('albums.id')),
    Column('genre_id', Integer, ForeignKey('genres.id'))
)

class Utilisateur(Base):
    __tablename__ = "utilisateurs"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)  # Nom_utilisateur
    password = Column(String)  # Mot_de_passe
    email = Column(String)  # Email
