"""
ISMS - Information Security Management System
Système de gestion de la sécurité de l'information

Auteur: toufik salah
Version: 2.0
Compatible: Python 3.10+
"""

import streamlit as st
import sqlite3
import pandas as pd
import hashlib
import json
import csv
from datetime import datetime, date
import os

# Initialisation de la session si nécessaire
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'confirm_reset' not in st.session_state:
    st.session_state.confirm_reset = False

# Configuration de la page Streamlit
st.set_page_config(
    page_title="ISMS - Système de Gestion de la Sécurité",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Classe principale pour la gestion de la base de données
class ISMSDatabase:
    def __init__(self, db_path="isms.db"):
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """Créer une connexion à la base de données"""
        return sqlite3.connect(self.db_path)
    
    def init_database(self):
        """Initialiser la base de données avec toutes les tables nécessaires"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Table des utilisateurs
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Table des politiques de sécurité
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            status TEXT DEFAULT 'Actif',
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Table des actifs informationnels
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS information_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            asset_type TEXT,
            criticality_level TEXT,
            owner TEXT,
            location TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Table d'évaluation des risques
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS risk_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            threat_name TEXT NOT NULL,
            threat_description TEXT,
            probability INTEGER CHECK(probability >= 1 AND probability <= 5),
            impact INTEGER CHECK(impact >= 1 AND impact <= 5),
            risk_level INTEGER,
            mitigation_measures TEXT,
            status TEXT DEFAULT 'Identifié',
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (asset_id) REFERENCES information_assets (id)
        )
        """)
        
        # Table des mesures de sécurité
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_measures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            priority TEXT,
            status TEXT DEFAULT 'À faire',
            responsible_person TEXT,
            due_date DATE,
            completion_date DATE,
            notes TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        conn.commit()
        conn.close()
        
        # Créer un utilisateur par défaut si aucun n'existe
        self.create_default_user()
    
    def create_default_user(self):
        """Créer un utilisateur par défaut admin/admin"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            password_hash = hashlib.sha256("admin".encode()).hexdigest()
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                ("admin", password_hash)
            )
            conn.commit()
        
        conn.close()
    
    def reset_database(self):
        """Réinitialiser complètement la base de données"""
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        self.init_database()

# Classe pour l'authentification
class AuthManager:
    def __init__(self, db):
        self.db = db
    
    def hash_password(self, password):
        """Hasher un mot de passe avec SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_user(self, username, password):
        """Vérifier les identifiants d'un utilisateur"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        password_hash = self.hash_password(password)
        cursor.execute(
            "SELECT id FROM users WHERE username = ? AND password_hash = ?",
            (username, password_hash)
        )
        
        result = cursor.fetchone()
        conn.close()
        
        return result is not None
    
    def create_user(self, username, password):
        """Créer un nouvel utilisateur"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        password_hash = self.hash_password(password)
        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            conn.close()
            return False

# Classe pour la gestion des politiques de sécurité
class SecurityPolicyManager:
    def __init__(self, db):
        self.db = db
    
    def add_policy(self, name, description, category):
        """Ajouter une nouvelle politique de sécurité"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO security_policies (name, description, category)
            VALUES (?, ?, ?)
        """, (name, description, category))
        
        conn.commit()
        conn.close()
    
    def get_all_policies(self):
        """Récupérer toutes les politiques de sécurité"""
        conn = self.db.get_connection()
        df = pd.read_sql_query("""
            SELECT id, name, description, category, status, created_date, updated_date
            FROM security_policies ORDER BY created_date DESC
        """, conn)
        conn.close()
        return df
    
    def update_policy(self, policy_id, name, description, category, status):
        """Mettre à jour une politique de sécurité"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE security_policies 
            SET name = ?, description = ?, category = ?, status = ?, updated_date = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (name, description, category, status, policy_id))
        
        conn.commit()
        conn.close()
    
    def delete_policy(self, policy_id):
        """Supprimer une politique de sécurité"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM security_policies WHERE id = ?", (policy_id,))
        
        conn.commit()
        conn.close()

# Classe pour la gestion des actifs informationnels
class AssetManager:
    def __init__(self, db):
        self.db = db
    
    def add_asset(self, name, description, asset_type, criticality_level, owner, location):
        """Ajouter un nouvel actif informationnel"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO information_assets (name, description, asset_type, criticality_level, owner, location)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, description, asset_type, criticality_level, owner, location))
        
        conn.commit()
        conn.close()
    
    def get_all_assets(self):
        """Récupérer tous les actifs informationnels"""
        conn = self.db.get_connection()
        df = pd.read_sql_query("""
            SELECT id, name, description, asset_type, criticality_level, owner, location, created_date
            FROM information_assets ORDER BY criticality_level DESC, name
        """, conn)
        conn.close()
        return df
    
    def get_assets_for_dropdown(self):
        """Récupérer les actifs pour les listes déroulantes"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM information_assets ORDER BY name")
        assets = cursor.fetchall()
        conn.close()
        return assets

# Classe pour l'évaluation des risques
class RiskManager:
    def __init__(self, db):
        self.db = db
    
    def add_risk(self, asset_id, threat_name, threat_description, probability, impact, mitigation_measures):
        """Ajouter une nouvelle évaluation de risque"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        risk_level = probability * impact
        
        cursor.execute("""
            INSERT INTO risk_assessments 
            (asset_id, threat_name, threat_description, probability, impact, risk_level, mitigation_measures)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (asset_id, threat_name, threat_description, probability, impact, risk_level, mitigation_measures))
        
        conn.commit()
        conn.close()
    
    def get_all_risks(self):
        """Récupérer toutes les évaluations de risques"""
        conn = self.db.get_connection()
        df = pd.read_sql_query("""
            SELECT 
                r.id, 
                a.name as asset_name,
                r.threat_name,
                r.threat_description,
                r.probability,
                r.impact,
                r.risk_level,
                r.mitigation_measures,
                r.status,
                r.created_date
            FROM risk_assessments r
            LEFT JOIN information_assets a ON r.asset_id = a.id
            ORDER BY r.risk_level DESC, r.created_date DESC
        """, conn)
        conn.close()
        return df
    
    def get_risk_level_color(self, risk_level):
        """Obtenir la couleur selon le niveau de risque"""
        if risk_level <= 5:
            return "🟢 Faible"
        elif risk_level <= 15:
            return "🟡 Moyen"
        else:
            return "🔴 Élevé"

# Classe pour la gestion des mesures de sécurité
class SecurityMeasureManager:
    def __init__(self, db):
        self.db = db
    
    def add_measure(self, name, description, category, priority, responsible_person, due_date, notes):
        """Ajouter une nouvelle mesure de sécurité"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO security_measures 
            (name, description, category, priority, responsible_person, due_date, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (name, description, category, priority, responsible_person, due_date, notes))
        
        conn.commit()
        conn.close()
    
    def get_all_measures(self):
        """Récupérer toutes les mesures de sécurité"""
        conn = self.db.get_connection()
        df = pd.read_sql_query("""
            SELECT id, name, description, category, priority, status, responsible_person, 
                   due_date, completion_date, notes, created_date
            FROM security_measures ORDER BY priority DESC, due_date ASC
        """, conn)
        conn.close()
        return df
    
    def update_measure_status(self, measure_id, new_status):
        """Mettre à jour le statut d'une mesure"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        completion_date = datetime.now().strftime('%Y-%m-%d') if new_status == 'Terminé' else None
        
        cursor.execute("""
            UPDATE security_measures 
            SET status = ?, completion_date = ?, updated_date = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (new_status, completion_date, measure_id))
        
        conn.commit()
        conn.close()

# Classe pour l'export des données
class DataExporter:
    def __init__(self, db):
        self.db = db
    
    def export_to_csv(self, table_name, data):
        """Exporter des données en CSV"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{table_name}_{timestamp}.csv"
        data.to_csv(filename, index=False, encoding='utf-8')
        return filename
    
    def export_to_json(self, table_name, data):
        """Exporter des données en JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{table_name}_{timestamp}.json"
        data.to_json(filename, orient='records', date_format='iso', indent=2)
        return filename
    
    def get_all_data_for_backup(self):
        """Récupérer toutes les données pour sauvegarde complète"""
        conn = self.db.get_connection()
        
        data = {
            'security_policies': pd.read_sql_query("SELECT * FROM security_policies", conn),
            'information_assets': pd.read_sql_query("SELECT * FROM information_assets", conn),
            'risk_assessments': pd.read_sql_query("SELECT * FROM risk_assessments", conn),
            'security_measures': pd.read_sql_query("SELECT * FROM security_measures", conn)
        }
        
        conn.close()
        return data
    
    def import_json_data(self, json_file):
        """Importer des données depuis un fichier JSON"""
        try:
            with open(json_file, 'r', encoding='utf-8') as file:
                data = json.load(file)

            conn = self.db.get_connection()
            cursor = conn.cursor()

            # Insertion des politiques de sécurité
            for policy in data.get('security_policies', []):
                cursor.execute("""
                    INSERT OR REPLACE INTO security_policies 
                    (id, name, description, category, status, created_date, updated_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (policy['id'], policy['name'], policy['description'], 
                     policy['category'], policy['status'], policy['created_date'], 
                     policy['updated_date']))

            # Insertion des actifs informationnels
            for asset in data.get('information_assets', []):
                cursor.execute("""
                    INSERT OR REPLACE INTO information_assets
                    (id, name, description, asset_type, criticality_level, owner, 
                     location, created_date, updated_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (asset['id'], asset['name'], asset['description'], 
                     asset['asset_type'], asset['criticality_level'], asset['owner'], 
                     asset['location'], asset['created_date'], asset['updated_date']))

            # Insertion des évaluations des risques
            for risk in data.get('risk_assessments', []):
                cursor.execute("""
                    INSERT OR REPLACE INTO risk_assessments
                    (id, asset_id, threat_name, threat_description, probability, 
                     impact, risk_level, mitigation_measures, status, created_date, 
                     updated_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (risk['id'], risk['asset_id'], risk['threat_name'], 
                     risk['threat_description'], risk['probability'], risk['impact'], 
                     risk['risk_level'], risk['mitigation_measures'], risk['status'], 
                     risk['created_date'], risk['updated_date']))

            # Insertion des mesures de sécurité
            for measure in data.get('security_measures', []):
                cursor.execute("""
                    INSERT OR REPLACE INTO security_measures
                    (id, name, description, category, priority, status, 
                     responsible_person, due_date, completion_date, notes, 
                     created_date, updated_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (measure['id'], measure['name'], measure['description'], 
                     measure['category'], measure['priority'], measure['status'], 
                     measure['responsible_person'], measure['due_date'], 
                     measure['completion_date'], measure['notes'], 
                     measure['created_date'], measure['updated_date']))

            conn.commit()
            conn.close()
            return True, "Données importées avec succès"
        except Exception as e:
            return False, f"Erreur lors de l'importation : {str(e)}"

# Initialisation des composants
@st.cache_resource
def init_components():
    db = ISMSDatabase()
    auth = AuthManager(db)
    policy_mgr = SecurityPolicyManager(db)
    asset_mgr = AssetManager(db)
    risk_mgr = RiskManager(db)
    measure_mgr = SecurityMeasureManager(db)
    exporter = DataExporter(db)
    
    return db, auth, policy_mgr, asset_mgr, risk_mgr, measure_mgr, exporter

# Interface de connexion
def login_page():
    st.title("🔐 ISMS - Connexion")
    st.markdown("---")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.subheader("Authentification")
        
        username = st.text_input("Nom d'utilisateur", placeholder="Entrez votre nom d'utilisateur")
        password = st.text_input("Mot de passe", type="password", placeholder="Entrez votre mot de passe")
        
        col_login, col_info = st.columns(2)
        
        with col_login:
            if st.button("Se connecter", type="primary", use_container_width=True):
                db, auth, _, _, _, _, _ = init_components()
                
                if auth.verify_user(username, password):
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.rerun()
                else:
                    st.error("Nom d'utilisateur ou mot de passe incorrect!")
        
        with col_info:
            with st.expander("ℹ️ Informations"):
                st.write("**Compte par défaut:**")
                st.write("- Utilisateur: `admin`")
                st.write("- Mot de passe: `admin`")

# Interface principale
def main_app():
    # Sidebar pour la navigation
    st.sidebar.title(f"👋 Bienvenue, {st.session_state.username}")
    st.sidebar.markdown("---")
    
    # Bouton de déconnexion
    if st.sidebar.button("🚪 Se déconnecter"):
        st.session_state.authenticated = False
        st.session_state.username = None
        st.rerun()
    
    st.sidebar.markdown("---")
    
    # Menu de navigation
    menu_options = [
        "📊 Tableau de bord",
        "📋 Politiques de sécurité", 
        "🏢 Actifs informationnels",
        "⚠️ Évaluation des risques",
        "🛡️ Mesures de sécurité",
        "📤 Export des données",
        "⚙️ Administration"
    ]
    
    selected_option = st.sidebar.selectbox("Navigation", menu_options)
    
    # Initialisation des composants
    db, auth, policy_mgr, asset_mgr, risk_mgr, measure_mgr, exporter = init_components()
    
    # Affichage selon l'option sélectionnée
    if selected_option == "📊 Tableau de bord":
        show_dashboard(policy_mgr, asset_mgr, risk_mgr, measure_mgr)
    
    elif selected_option == "📋 Politiques de sécurité":
        show_security_policies(policy_mgr)
    
    elif selected_option == "🏢 Actifs informationnels":
        show_information_assets(asset_mgr)
    
    elif selected_option == "⚠️ Évaluation des risques":
        show_risk_assessment(risk_mgr, asset_mgr)
    
    elif selected_option == "🛡️ Mesures de sécurité":
        show_security_measures(measure_mgr)
    
    elif selected_option == "📤 Export des données":
        show_data_export(exporter, policy_mgr, asset_mgr, risk_mgr, measure_mgr)
    
    elif selected_option == "⚙️ Administration":
        show_administration(db, auth)

# Tableau de bord
def show_dashboard(policy_mgr, asset_mgr, risk_mgr, measure_mgr):
    st.title("📊 Tableau de bord ISMS")
    st.markdown("---")
    
    # Métriques principales
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        policies_count = len(policy_mgr.get_all_policies())
        st.metric("Politiques de sécurité", policies_count, delta=None)
    
    with col2:
        assets_count = len(asset_mgr.get_all_assets())
        st.metric("Actifs informationnels", assets_count, delta=None)
    
    with col3:
        risks_count = len(risk_mgr.get_all_risks())
        st.metric("Risques identifiés", risks_count, delta=None)
    
    with col4:
        measures_count = len(measure_mgr.get_all_measures())
        st.metric("Mesures de sécurité", measures_count, delta=None)
    
    st.markdown("---")
    
    # Graphiques et analyses
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Répartition des risques par niveau")
        risks_df = risk_mgr.get_all_risks()
        if not risks_df.empty:
            risk_categories = risks_df['risk_level'].apply(lambda x: 
                "Faible (1-5)" if x <= 5 else "Moyen (6-15)" if x <= 15 else "Élevé (16-25)"
            ).value_counts()
            st.bar_chart(risk_categories)
        else:
            st.info("Aucun risque évalué pour le moment")
    
    with col2:
        st.subheader("📈 État des mesures de sécurité")
        measures_df = measure_mgr.get_all_measures()
        if not measures_df.empty:
            status_counts = measures_df['status'].value_counts()
            st.bar_chart(status_counts)
        else:
            st.info("Aucune mesure de sécurité enregistrée")
    
    # Alertes et notifications
    st.markdown("---")
    st.subheader("🚨 Alertes et notifications")
    
    # Risques élevés
    high_risks = risks_df[risks_df['risk_level'] > 15] if not risks_df.empty else pd.DataFrame()
    if not high_risks.empty:
        st.error(f"⚠️ {len(high_risks)} risque(s) de niveau élevé détecté(s) !")
        st.dataframe(high_risks[['asset_name', 'threat_name', 'risk_level']], use_container_width=True)
    
    # Mesures en retard
    measures_df = measure_mgr.get_all_measures()
    if not measures_df.empty:
        measures_df['due_date'] = pd.to_datetime(measures_df['due_date'])
        overdue_measures = measures_df[
            (measures_df['due_date'] < pd.Timestamp.now()) & 
            (measures_df['status'] != 'Terminé')
        ]
        if not overdue_measures.empty:
            st.warning(f"📅 {len(overdue_measures)} mesure(s) de sécurité en retard !")
            st.dataframe(overdue_measures[['name', 'responsible_person', 'due_date']], use_container_width=True)

# Gestion des politiques de sécurité
def show_security_policies(policy_mgr):
    st.title("📋 Gestion des politiques de sécurité")
    st.markdown("---")
    
    tab1, tab2 = st.tabs(["📝 Ajouter une politique", "📋 Liste des politiques"])
    
    with tab1:
        st.subheader("Nouvelle politique de sécurité")
        
        with st.form("add_policy_form"):
            name = st.text_input("Nom de la politique *", placeholder="Ex: Politique de mots de passe")
            category = st.selectbox("Catégorie", [
                "Contrôle d'accès", "Sécurité physique", "Gestion des incidents", 
                "Formation", "Gestion des données", "Continuité d'activité", "Autre"
            ])
            description = st.text_area("Description", placeholder="Description détaillée de la politique...")
            
            submitted = st.form_submit_button("➕ Ajouter la politique", type="primary")
            
            if submitted:
                if name:
                    policy_mgr.add_policy(name, description, category)
                    st.success("✅ Politique ajoutée avec succès !")
                    st.rerun()
                else:
                    st.error("Le nom de la politique est obligatoire !")
    
    with tab2:
        st.subheader("Liste des politiques existantes")
        
        policies_df = policy_mgr.get_all_policies()
        
        if not policies_df.empty:
            # Filtre par catégorie
            categories = ["Toutes"] + policies_df['category'].unique().tolist()
            selected_category = st.selectbox("Filtrer par catégorie", categories)
            
            if selected_category != "Toutes":
                policies_df = policies_df[policies_df['category'] == selected_category]
            
            # Affichage des politiques
            for _, policy in policies_df.iterrows():
                with st.expander(f"📋 {policy['name']} - {policy['category']}"):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.write(f"**Description:** {policy['description']}")
                        st.write(f"**Statut:** {policy['status']}")
                        st.write(f"**Créée le:** {policy['created_date']}")
                    
                    with col2:
                        if st.button(f"🗑️ Supprimer", key=f"del_policy_{policy['id']}"):
                            policy_mgr.delete_policy(policy['id'])
                            st.success("Politique supprimée !")
                            st.rerun()
        else:
            st.info("Aucune politique de sécurité enregistrée.")

# Gestion des actifs informationnels
def show_information_assets(asset_mgr):
    st.title("🏢 Gestion des actifs informationnels")
    st.markdown("---")
    
    tab1, tab2 = st.tabs(["➕ Ajouter un actif", "📋 Liste des actifs"])
    
    with tab1:
        st.subheader("Nouvel actif informationnel")
        
        with st.form("add_asset_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                name = st.text_input("Nom de l'actif *", placeholder="Ex: Serveur de base de données")
                asset_type = st.selectbox("Type d'actif", [
                    "Matériel", "Logiciel", "Données", "Personnel", "Service", 
                    "Documentation", "Infrastructure", "Autre"
                ])
                criticality_level = st.selectbox("Niveau de criticité", [
                    "Critique", "Élevé", "Moyen", "Faible"
                ])
            
            with col2:
                owner = st.text_input("Responsable", placeholder="Nom du responsable")
                location = st.text_input("Localisation", placeholder="Emplacement physique/logique")
            
            description = st.text_area("Description", placeholder="Description détaillée de l'actif...")
            
            submitted = st.form_submit_button("➕ Ajouter l'actif", type="primary")
            
            if submitted:
                if name:
                    asset_mgr.add_asset(name, description, asset_type, criticality_level, owner, location)
                    st.success("✅ Actif ajouté avec succès !")
                    st.rerun()
                else:
                    st.error("Le nom de l'actif est obligatoire !")
    
    with tab2:
        st.subheader("Liste des actifs informationnels")
        
        assets_df = asset_mgr.get_all_assets()
        
        if not assets_df.empty:
            # Filtres
            col1, col2 = st.columns(2)
            with col1:
                types = ["Tous"] + assets_df['asset_type'].unique().tolist()
                selected_type = st.selectbox("Filtrer par type", types)
            
            with col2:
                criticalities = ["Toutes"] + assets_df['criticality_level'].unique().tolist()
                selected_criticality = st.selectbox("Filtrer par criticité", criticalities)
            
            # Application des filtres
            filtered_df = assets_df.copy()
            if selected_type != "Tous":
                filtered_df = filtered_df[filtered_df['asset_type'] == selected_type]
            if selected_criticality != "Toutes":
                filtered_df = filtered_df[filtered_df['criticality_level'] == selected_criticality]
            
            # Affichage
            st.dataframe(
                filtered_df[['name', 'asset_type', 'criticality_level', 'owner', 'location', 'created_date']], 
                use_container_width=True
            )
            
        else:
            st.info("Aucun actif informationnel enregistré.")

# Évaluation des risques
def show_risk_assessment(risk_mgr, asset_mgr):
    st.title("⚠️ Évaluation des risques")
    st.markdown("---")
    
    tab1, tab2 = st.tabs(["📊 Ajouter un risque", "📋 Matrice des risques"])
    
    with tab1:
        st.subheader("Nouvelle évaluation de risque")
        
        # Récupérer la liste des actifs
        assets = asset_mgr.get_assets_for_dropdown()
        
        if not assets:
            st.warning("⚠️ Aucun actif informationnel disponible. Veuillez d'abord créer des actifs.")
            return
        
        with st.form("add_risk_form"):
            # Sélection de l'actif
            asset_options = {f"{asset[1]} (ID: {asset[0]})": asset[0] for asset in assets}
            selected_asset = st.selectbox("Actif concerné *", list(asset_options.keys()))
            asset_id = asset_options[selected_asset]
            
            # Informations sur la menace
            threat_name = st.text_input("Nom de la menace *", placeholder="Ex: Attaque par déni de service")
            threat_description = st.text_area("Description de la menace", 
                                             placeholder="Description détaillée de la menace...")
            
            # Évaluation
            col1, col2, col3 = st.columns(3)
            
            with col1:
                probability = st.selectbox("Probabilité *", [1, 2, 3, 4, 5], 
                                         format_func=lambda x: f"{x} - {'Très faible' if x==1 else 'Faible' if x==2 else 'Moyen' if x==3 else 'Élevé' if x==4 else 'Très élevé'}")
            
            with col2:
                impact = st.selectbox("Impact *", [1, 2, 3, 4, 5], 
                                    format_func=lambda x: f"{x} - {'Très faible' if x==1 else 'Faible' if x==2 else 'Moyen' if x==3 else 'Élevé' if x==4 else 'Très élevé'}")
            
            with col3:
                risk_level_preview = probability * impact
                color = "🟢" if risk_level_preview <= 5 else "🟡" if risk_level_preview <= 15 else "🔴"
                st.metric("Niveau de risque", f"{color} {risk_level_preview}")
            
            # Mesures d'atténuation
            mitigation_measures = st.text_area("Mesures d'atténuation proposées", 
                                             placeholder="Actions pour réduire le risque...")
            
            submitted = st.form_submit_button("➕ Ajouter l'évaluation", type="primary")
            
            if submitted:
                if threat_name:
                    risk_mgr.add_risk(asset_id, threat_name, threat_description, 
                                    probability, impact, mitigation_measures)
                    st.success("✅ Évaluation de risque ajoutée avec succès !")
                    st.rerun()
                else:
                    st.error("Le nom de la menace est obligatoire !")
    
    with tab2:
        st.subheader("Matrice des risques")
        
        risks_df = risk_mgr.get_all_risks()
        
        if not risks_df.empty:
            # Statistiques rapides
            col1, col2, col3 = st.columns(3)
            
            with col1:
                high_risks = len(risks_df[risks_df['risk_level'] > 15])
                st.metric("Risques élevés", high_risks, delta=None)
            
            with col2:
                medium_risks = len(risks_df[(risks_df['risk_level'] > 5) & (risks_df['risk_level'] <= 15)])
                st.metric("Risques moyens", medium_risks, delta=None)
            
            with col3:
                low_risks = len(risks_df[risks_df['risk_level'] <= 5])
                st.metric("Risques faibles", low_risks, delta=None)
            
            # Tableau des risques avec couleurs
            st.subheader("📊 Tableau détaillé des risques")
            
            # Ajouter une colonne avec les couleurs
            risks_display = risks_df.copy()
            risks_display['Niveau'] = risks_display['risk_level'].apply(
                lambda x: f"🔴 Élevé ({x})" if x > 15 else f"🟡 Moyen ({x})" if x > 5 else f"🟢 Faible ({x})"
            )
            
            # Affichage du tableau
            st.dataframe(
                risks_display[['asset_name', 'threat_name', 'probability', 'impact', 'Niveau', 'status', 'created_date']], 
                use_container_width=True,
                column_config={
                    "asset_name": "Actif",
                    "threat_name": "Menace",
                    "probability": "Probabilité",
                    "impact": "Impact",
                    "Niveau": "Risque",
                    "status": "Statut",
                    "created_date": "Date de création"
                }
            )
            
        else:
            st.info("Aucune évaluation de risque effectuée.")

# Gestion des mesures de sécurité
def show_security_measures(measure_mgr):
    st.title("🛡️ Gestion des mesures de sécurité")
    st.markdown("---")
    
    tab1, tab2 = st.tabs(["➕ Ajouter une mesure", "📋 Suivi des mesures"])
    
    with tab1:
        st.subheader("Nouvelle mesure de sécurité")
        
        with st.form("add_measure_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                name = st.text_input("Nom de la mesure *", placeholder="Ex: Installation d'un antivirus")
                category = st.selectbox("Catégorie", [
                    "Préventive", "Détective", "Corrective", "Administrative", 
                    "Technique", "Physique", "Autre"
                ])
                priority = st.selectbox("Priorité", ["Critique", "Élevée", "Moyenne", "Faible"])
            
            with col2:
                responsible_person = st.text_input("Responsable", placeholder="Nom du responsable")
                due_date = st.date_input("Date d'échéance")
            
            description = st.text_area("Description", placeholder="Description détaillée de la mesure...")
            notes = st.text_area("Notes supplémentaires", placeholder="Informations complémentaires...")
            
            submitted = st.form_submit_button("➕ Ajouter la mesure", type="primary")
            
            if submitted:
                if name:
                    measure_mgr.add_measure(name, description, category, priority, 
                                          responsible_person, due_date, notes)
                    st.success("✅ Mesure de sécurité ajoutée avec succès !")
                    st.rerun()
                else:
                    st.error("Le nom de la mesure est obligatoire !")
    
    with tab2:
        st.subheader("Suivi des mesures de sécurité")
        
        measures_df = measure_mgr.get_all_measures()
        
        if not measures_df.empty:
            # Filtres
            col1, col2, col3 = st.columns(3)
            
            with col1:
                statuses = ["Tous"] + measures_df['status'].unique().tolist()
                selected_status = st.selectbox("Filtrer par statut", statuses)
            
            with col2:
                priorities = ["Toutes"] + measures_df['priority'].unique().tolist()
                selected_priority = st.selectbox("Filtrer par priorité", priorities)
            
            with col3:
                categories = ["Toutes"] + measures_df['category'].unique().tolist()
                selected_category = st.selectbox("Filtrer par catégorie", categories)
            
            # Application des filtres
            filtered_df = measures_df.copy()
            if selected_status != "Tous":
                filtered_df = filtered_df[filtered_df['status'] == selected_status]
            if selected_priority != "Toutes":
                filtered_df = filtered_df[filtered_df['priority'] == selected_priority]
            if selected_category != "Toutes":
                filtered_df = filtered_df[filtered_df['category'] == selected_category]
            
            # Affichage des mesures
            for _, measure in filtered_df.iterrows():
                # Couleur selon le statut
                status_color = {
                    "À faire": "🔴",
                    "En cours": "🟡", 
                    "Terminé": "🟢"
                }.get(measure['status'], "⚪")
                
                with st.expander(f"{status_color} {measure['name']} - {measure['priority']} priorité"):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.write(f"**Description:** {measure['description']}")
                        st.write(f"**Catégorie:** {measure['category']}")
                        st.write(f"**Responsable:** {measure['responsible_person']}")
                        st.write(f"**Échéance:** {measure['due_date']}")
                        if measure['completion_date']:
                            st.write(f"**Terminé le:** {measure['completion_date']}")
                        if measure['notes']:
                            st.write(f"**Notes:** {measure['notes']}")
                    
                    with col2:
                        new_status = st.selectbox(
                            "Changer le statut", 
                            ["À faire", "En cours", "Terminé"],
                            index=["À faire", "En cours", "Terminé"].index(measure['status']),
                            key=f"status_{measure['id']}"
                        )
                        
                        if st.button(f"Mettre à jour", key=f"update_{measure['id']}"):
                            measure_mgr.update_measure_status(measure['id'], new_status)
                            st.success("Statut mis à jour !")
                            st.rerun()
        else:
            st.info("Aucune mesure de sécurité enregistrée.")

# Export des données
def show_data_export(exporter, policy_mgr, asset_mgr, risk_mgr, measure_mgr):
    st.title("📤 Export des données")
    st.markdown("---")
    
    st.subheader("Exporter les données du système ISMS")
    st.info("💡 Vous pouvez exporter vos données en format CSV ou JSON pour archivage ou analyse externe.")
    
    # Sélection des données à exporter
    export_options = st.multiselect(
        "Sélectionnez les données à exporter",
        ["Politiques de sécurité", "Actifs informationnels", "Évaluations des risques", "Mesures de sécurité"],
        default=["Politiques de sécurité", "Actifs informationnels", "Évaluations des risques", "Mesures de sécurité"]
    )
    
    # Format d'export
    export_format = st.radio("Format d'export", ["CSV", "JSON"])
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📁 Export sélectif", type="primary", use_container_width=True):
            if not export_options:
                st.error("Veuillez sélectionner au moins un type de données à exporter !")
                return
            
            files_created = []
            
            for option in export_options:
                if option == "Politiques de sécurité":
                    data = policy_mgr.get_all_policies()
                    table_name = "politiques_securite"
                elif option == "Actifs informationnels":
                    data = asset_mgr.get_all_assets()
                    table_name = "actifs_informationnels"
                elif option == "Évaluations des risques":
                    data = risk_mgr.get_all_risks()
                    table_name = "evaluations_risques"
                elif option == "Mesures de sécurité":
                    data = measure_mgr.get_all_measures()
                    table_name = "mesures_securite"
                
                if not data.empty:
                    if export_format == "CSV":
                        filename = exporter.export_to_csv(table_name, data)
                    else:
                        filename = exporter.export_to_json(table_name, data)
                    files_created.append(filename)
            
            if files_created:
                st.success(f"✅ {len(files_created)} fichier(s) exporté(s) avec succès !")
                for file in files_created:
                    st.write(f"📁 {file}")
            else:
                st.warning("Aucune donnée à exporter.")
    
    with col2:
        if st.button("💾 Export complet", type="secondary", use_container_width=True):
            all_data = exporter.get_all_data_for_backup()
            files_created = []
            
            for table_name, data in all_data.items():
                if not data.empty:
                    if export_format == "CSV":
                        filename = exporter.export_to_csv(table_name, data)
                    else:
                        filename = exporter.export_to_json(table_name, data)
                    files_created.append(filename)
            
            if files_created:
                st.success(f"✅ Sauvegarde complète effectuée ! {len(files_created)} fichier(s) créé(s).")
                for file in files_created:
                    st.write(f"📁 {file}")
            else:
                st.warning("Aucune donnée à sauvegarder.")
    
    # Aperçu des données
    st.markdown("---")
    st.subheader("👀 Aperçu des données disponibles")
    
    preview_tabs = st.tabs(["Politiques", "Actifs", "Risques", "Mesures"])
    
    with preview_tabs[0]:
        policies_df = policy_mgr.get_all_policies()
        if not policies_df.empty:
            st.dataframe(policies_df.head(), use_container_width=True)
        else:
            st.info("Aucune politique disponible")
    
    with preview_tabs[1]:
        assets_df = asset_mgr.get_all_assets()
        if not assets_df.empty:
            st.dataframe(assets_df.head(), use_container_width=True)
        else:
            st.info("Aucun actif disponible")
    
    with preview_tabs[2]:
        risks_df = risk_mgr.get_all_risks()
        if not risks_df.empty:
            st.dataframe(risks_df.head(), use_container_width=True)
        else:
            st.info("Aucun risque disponible")
    
    with preview_tabs[3]:
        measures_df = measure_mgr.get_all_measures()
        if not measures_df.empty:
            st.dataframe(measures_df.head(), use_container_width=True)
        else:
            st.info("Aucune mesure disponible")

# Administration
def show_administration(db, auth):
    st.title("⚙️ Administration système")
    st.markdown("---")
    
    tab1, tab2, tab3 = st.tabs(["👥 Gestion des utilisateurs", "🗃️ Base de données", "ℹ️ Informations système"])
    
    with tab1:
        st.subheader("Création d'un nouvel utilisateur")
        
        with st.form("create_user_form"):
            new_username = st.text_input("Nom d'utilisateur", placeholder="Nouveau nom d'utilisateur")
            new_password = st.text_input("Mot de passe", type="password", placeholder="Mot de passe")
            confirm_password = st.text_input("Confirmer le mot de passe", type="password", placeholder="Confirmer le mot de passe")
            
            submitted = st.form_submit_button("👤 Créer l'utilisateur", type="primary")
            
            if submitted:
                if not new_username or not new_password:
                    st.error("Tous les champs sont obligatoires !")
                elif new_password != confirm_password:
                    st.error("Les mots de passe ne correspondent pas !")
                else:
                    if auth.create_user(new_username, new_password):
                        st.success("✅ Utilisateur créé avec succès !")
                    else:
                        st.error("❌ Ce nom d'utilisateur existe déjà !")
    
    with tab2:
        st.subheader("Gestion de la base de données")
        
        # Section d'import de données
        st.markdown("### 📥 Import de données")
        uploaded_file = st.file_uploader("Choisir un fichier JSON à importer", type=['json'])
        if uploaded_file is not None:
            # Sauvegarder temporairement le fichier
            with open("temp_import.json", "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            if st.button("📤 Importer les données", type="primary"):
                success, message = DataExporter(db).import_json_data("temp_import.json")
                if success:
                    st.success(f"✅ {message}")
                else:
                    st.error(f"❌ {message}")
                
                # Supprimer le fichier temporaire
                if os.path.exists("temp_import.json"):
                    os.remove("temp_import.json")

        st.markdown("---")
        st.markdown("### 🗑️ Réinitialisation")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.info("⚠️ **Attention :** La réinitialisation supprimera toutes les données existantes de manière irréversible.")
            
            if st.button("🗑️ Réinitialiser la base de données", type="secondary"):
                if 'confirm_reset' not in st.session_state:
                    st.session_state.confirm_reset = True
                    st.rerun()
        
        with col2:
            if st.session_state.get('confirm_reset', False):
                st.warning("⚠️ Êtes-vous sûr de vouloir réinitialiser la base de données ?")
                
                col_yes, col_no = st.columns(2)
                with col_yes:
                    if st.button("✅ Oui, réinitialiser", type="primary"):
                        db.reset_database()
                        st.session_state.confirm_reset = False
                        st.success("✅ Base de données réinitialisée avec succès !")
                        st.rerun()
                
                with col_no:
                    if st.button("❌ Annuler"):
                        st.session_state.confirm_reset = False
                        st.rerun()
        
        # Statistiques de la base de données
        st.markdown("---")
        st.subheader("📊 Statistiques de la base de données")
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Compter les enregistrements par table
        tables_stats = {}
        tables = ['security_policies', 'information_assets', 'risk_assessments', 'security_measures', 'users']
        
        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            tables_stats[table] = count
        
        conn.close()
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Politiques", tables_stats['security_policies'])
            st.metric("Actifs", tables_stats['information_assets'])
        
        with col2:
            st.metric("Risques", tables_stats['risk_assessments'])
            st.metric("Mesures", tables_stats['security_measures'])
        
        with col3:
            st.metric("Utilisateurs", tables_stats['users'])
    
    with tab3:
        st.subheader("Informations système")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**🔧 Informations techniques**")
            st.write(f"- Version Python: {st.__version__}")
            st.write(f"- Version Streamlit: {st.__version__}")
            st.write(f"- Base de données: SQLite")
            st.write(f"- Fichier DB: `isms.db`")
        
        with col2:
            st.write("**📋 Fonctionnalités disponibles**")
            st.write("- ✅ Gestion des politiques de sécurité")
            st.write("- ✅ Gestion des actifs informationnels")
            st.write("- ✅ Évaluation des risques")
            st.write("- ✅ Suivi des mesures de sécurité")
            st.write("- ✅ Export des données (CSV/JSON)")
            st.write("- ✅ Authentification sécurisée")
        
        st.markdown("---")
        st.write("**📖 Guide d'utilisation**")
        with st.expander("Comment utiliser ce système ISMS"):
            st.markdown("""
            1. **Commencez par créer des actifs informationnels** dans la section dédiée
            2. **Définissez vos politiques de sécurité** selon vos besoins organisationnels
            3. **Effectuez des évaluations de risques** pour chaque actif critique
            4. **Planifiez et suivez des mesures de sécurité** pour atténuer les risques
            5. **Exportez régulièrement vos données** pour archivage et reporting
            6. **Consultez le tableau de bord** pour une vue d'ensemble de votre posture sécuritaire
            """)

# Point d'entrée principal
def main():
    # Initialisation des variables de session
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'username' not in st.session_state:
        st.session_state.username = None
    
    # Affichage selon l'état d'authentification
    if not st.session_state.authenticated:
        login_page()
    else:
        main_app()

if __name__ == "__main__":
    main()