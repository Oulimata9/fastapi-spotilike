-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Hôte : 127.0.0.1:3306
-- Généré le : mer. 17 jan. 2024 à 23:47
-- Version du serveur : 8.2.0
-- Version de PHP : 8.2.13

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de données : `spotilike_db`
--

-- --------------------------------------------------------

--
-- Structure de la table `album`
--

DROP TABLE IF EXISTS `album`;
CREATE TABLE IF NOT EXISTS `album` (
  `IDalbum` int NOT NULL AUTO_INCREMENT,
  `Titre` varchar(255) NOT NULL,
  `Pochette` longblob,
  `Date_sortie` date DEFAULT NULL,
  `liste_morceaux` varchar(45) DEFAULT NULL,
  `Artiste_ID` int DEFAULT NULL,
  PRIMARY KEY (`IDalbum`),
  KEY `Artiste_ID` (`Artiste_ID`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Déchargement des données de la table `album`
--

INSERT INTO `album` (`IDalbum`, `Titre`, `Pochette`, `Date_sortie`, `liste_morceaux`, `Artiste_ID`) VALUES
(1, 'Album1', 0x6c69656e5f706f636865747465312e6a7067, '2022-01-01', NULL, 1),
(2, 'Album2', 0x6c69656e5f706f636865747465322e6a7067, '2022-02-01', NULL, 2);

-- --------------------------------------------------------

--
-- Structure de la table `artiste`
--

DROP TABLE IF EXISTS `artiste`;
CREATE TABLE IF NOT EXISTS `artiste` (
  `IDartiste` int NOT NULL AUTO_INCREMENT,
  `Nom_artiste` varchar(255) NOT NULL,
  `Avatar` longblob,
  `Biographie` text,
  PRIMARY KEY (`IDartiste`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Déchargement des données de la table `artiste`
--

INSERT INTO `artiste` (`IDartiste`, `Nom_artiste`, `Avatar`, `Biographie`) VALUES
(1, 'Artiste1', 0x6c69656e5f617661746172312e6a7067, 'Biographie de l\'artiste 1'),
(2, 'Artiste2', 0x6c69656e5f617661746172322e6a7067, 'Biographie de l\'artiste 2');

-- --------------------------------------------------------

--
-- Structure de la table `genre`
--

DROP TABLE IF EXISTS `genre`;
CREATE TABLE IF NOT EXISTS `genre` (
  `IDgenre` int NOT NULL AUTO_INCREMENT,
  `Titre` varchar(255) NOT NULL,
  `Description` text,
  PRIMARY KEY (`IDgenre`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Déchargement des données de la table `genre`
--

INSERT INTO `genre` (`IDgenre`, `Titre`, `Description`) VALUES
(1, 'Pop', 'Musique populaire'),
(2, 'Rock', 'Musique rock'),
(5, 'Pop', 'Musique populaire'),
(6, 'Rock', 'Musique rock');

-- --------------------------------------------------------

--
-- Structure de la table `morceau`
--

DROP TABLE IF EXISTS `morceau`;
CREATE TABLE IF NOT EXISTS `morceau` (
  `IDmorceau` int NOT NULL AUTO_INCREMENT,
  `Titre` varchar(255) NOT NULL,
  `Duree` time DEFAULT NULL,
  `artisteID` int DEFAULT NULL,
  `Genre_ID` int DEFAULT NULL,
  `Album_ID` int DEFAULT NULL,
  PRIMARY KEY (`IDmorceau`),
  KEY `artisteID` (`artisteID`),
  KEY `Genre_ID` (`Genre_ID`),
  KEY `Album_ID` (`Album_ID`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Déchargement des données de la table `morceau`
--

INSERT INTO `morceau` (`IDmorceau`, `Titre`, `Duree`, `artisteID`, `Genre_ID`, `Album_ID`) VALUES
(13, 'Morceau1', '03:30:00', 1, 1, 1),
(14, 'Morceau2', '04:15:00', 2, 2, 2);

-- --------------------------------------------------------

--
-- Structure de la table `utilisateur`
--

DROP TABLE IF EXISTS `utilisateur`;
CREATE TABLE IF NOT EXISTS `utilisateur` (
  `IDutilisateur` int NOT NULL AUTO_INCREMENT,
  `Nom_utilisateur` varchar(255) NOT NULL,
  `Mot_de_passe` varchar(255) NOT NULL,
  `Email` varchar(255) NOT NULL,
  PRIMARY KEY (`IDutilisateur`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Déchargement des données de la table `utilisateur`
--

INSERT INTO `utilisateur` (`IDutilisateur`, `Nom_utilisateur`, `Mot_de_passe`, `Email`) VALUES
(1, 'Utilisateur1', 'mot_de_passe1', 'utilisateur1@email.com'),
(2, 'Utilisateur2', 'mot_de_passe2', 'utilisateur2@email.com');

--
-- Contraintes pour les tables déchargées
--

--
-- Contraintes pour la table `album`
--
ALTER TABLE `album`
  ADD CONSTRAINT `Artiste_ID` FOREIGN KEY (`Artiste_ID`) REFERENCES `artiste` (`IDartiste`);

--
-- Contraintes pour la table `morceau`
--
ALTER TABLE `morceau`
  ADD CONSTRAINT `Album_ID` FOREIGN KEY (`Album_ID`) REFERENCES `album` (`IDalbum`),
  ADD CONSTRAINT `artisteID` FOREIGN KEY (`artisteID`) REFERENCES `artiste` (`IDartiste`),
  ADD CONSTRAINT `Genre_ID` FOREIGN KEY (`Genre_ID`) REFERENCES `genre` (`IDgenre`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
