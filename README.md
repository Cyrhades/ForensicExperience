# ForensicExperience 

**ForensicExperience** est une interface graphique (GUI) avancée pour **Volatility 2**, conçue pour simplifier l'analyse forensique de la mémoire vive (RAM). Elle intègre des fonctionnalités modernes comme l'intelligence artificielle pour la détection de menaces et un éditeur hexadécimal intégré.

## Fonctionnalités Clés

- **IA Threat Intelligence** : Analyse automatique de l'arbre des processus par IA (Ollama/Llama3) pour détecter les comportements suspects (Process Hollowing, DLL Injection, Reverse Shells).
- **Hierarchical Highlighting** : Visualisation claire des menaces (Rouge pour les suspects, Jaune pour les descendants).
- **Hex Viewer Intégré** : Inspection binaire directe des processus extraits avec pagination haute performance.
- **Extraction Facile** : Extraction en un clic des processus (`procdump`) et des fichiers (`dumpfiles`) depuis la mémoire.
- **Security Suite** : Hashdump automatique et module de cassage de mots de passe (Bruteforce/Wordlist) avec support NTLM.
- **Dashboard Complet** : Identification automatique du profil, de l'architecture, du nom de la machine et des utilisateurs.
- **Multi-langue** : Support complet du Français et de l'Anglais.

## Installation

1. **Prérequis** :
   - Python 3.x
   - Volatility 2 (placé dans le dossier `bin/`)
   - Ollama (optionnel, pour l'IA locale)

2. **Installation des dépendances** :
   ```bash
   pip install requests
   ```

3. **Lancement** :
   ```bash
   python vol_gui.py
   ```


## Structure du Projet

- `vol_gui.py` : Cœur de l'application (Tkinter).
- `locales/` : Fichiers de traduction JSON.
- `bin/` : Emplacement recommandé pour les binaires Volatility.
- `extracted/` : Dossier de sortie pour les dumps de processus et fichiers.


## Licence

Ce projet est conçu à des fins éducatives et de recherche en cybersécurité. L'utilisation responsable est de mise.
