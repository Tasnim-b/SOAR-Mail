# core/services/email_analyzer.py
import re
import logging
from typing import Dict, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class EmailAnalyzer:
    """Analyseur d'emails pour détecter les menaces"""
    
    def __init__(self):
        # Règles de détection
        self.phishing_keywords = [
            'mot de passe', 'password', 'compte', 'account', 'verification',
            'urgent', 'important', 'action requise', 'sécurité', 'security',
            'banque', 'bank', 'paypal', 'facebook', 'google', 'microsoft',
            'mise à jour', 'update', 'confirmation', 'verify', 'click here',
            'cliquez ici', 'login', 'connexion', 'reset', 'réinitialiser'
        ]
        
        self.spam_keywords = [
            'gagner', 'gratuit', 'free', 'prix', 'lottery', 'loterie',
            'offre spéciale', 'special offer', 'réduction', 'discount',
            'urgent', 'important', 'opportunité', 'opportunity'
        ]
        
        self.suspicious_domains = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'  # Domains personnels souvent utilisés pour le spam
        ]
        
        self.dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
            '.scr', '.pif', '.com', '.hta', '.msi', '.dll'
        ]
    
    def analyze(self, email_data: Dict) -> Tuple[str, str, int]:
        """
        Analyse un email et retourne:
        - threat_level: SAFE, LOW, MEDIUM, HIGH, CRITICAL
        - threat_type: PHISHING, SPAM, MALWARE, SUSPICIOUS, SPOOFING, NONE
        - risk_score: Score de risque de 0 à 100
        """
        risk_score = 0
        threats_detected = []
        
        # 1. Vérifier le sujet
        subject = email_data.get('subject', '').lower()
        risk_score += self._analyze_subject(subject)
        
        # 2. Vérifier le corps
        body_text = email_data.get('body_text', '').lower()
        body_html = email_data.get('body_html', '').lower()
        risk_score += self._analyze_body(body_text, body_html)
        
        # 3. Vérifier l'expéditeur
        sender = email_data.get('sender', '').lower()
        risk_score += self._analyze_sender(sender)
        
        # 4. Vérifier les pièces jointes
        attachments = email_data.get('attachments', [])
        risk_score += self._analyze_attachments(attachments)
        
        # 5. Vérifier les URLs
        urls = self._extract_urls(body_text + body_html)
        risk_score += self._analyze_urls(urls)
        
        # Déterminer le niveau de menace
        threat_level, threat_type = self._determine_threat(risk_score, threats_detected)
        
        return threat_level, threat_type, risk_score
    
    def _analyze_subject(self, subject: str) -> int:
        """Analyse le sujet de l'email"""
        score = 0
        
        # Vérifier les mots-clés de phishing
        for keyword in self.phishing_keywords:
            if keyword in subject:
                score += 10
        
        # Vérifier les mots-clés de spam
        for keyword in self.spam_keywords:
            if keyword in subject:
                score += 5
        
        # Vérifier les caractères suspects
        if '!!!' in subject or '???' in subject:
            score += 5
        
        # Vérifier les majuscules excessives
        if len(subject) > 10:
            uppercase_ratio = sum(1 for c in subject if c.isupper()) / len(subject)
            if uppercase_ratio > 0.5:
                score += 10
        
        return min(score, 30)
    
    def _analyze_body(self, body_text: str, body_html: str) -> int:
        """Analyse le corps de l'email"""
        score = 0
        full_body = body_text + body_html
        
        # Vérifier les mots-clés de phishing
        for keyword in self.phishing_keywords:
            if keyword in full_body:
                score += 5
        
        # Vérifier les liens suspects
        if 'href=' in body_html and 'http' in body_html:
            score += 10
        
        # Vérifier les formulaires
        if '<form' in body_html or 'input type' in body_html:
            score += 15
        
        return min(score, 30)
    
    def _analyze_sender(self, sender: str) -> int:
        """Analyse l'expéditeur"""
        score = 0
        
        # Vérifier les domaines suspects
        for domain in self.suspicious_domains:
            if domain in sender:
                score += 5
        
        # Vérifier les adresses génériques
        if 'noreply' in sender or 'no-reply' in sender:
            score += 3
        
        # Vérifier les adresses masquées
        if '...' in sender or '***' in sender:
            score += 10
        
        return min(score, 20)
    
    def _analyze_attachments(self, attachments: list) -> int:
        """Analyse les pièces jointes"""
        score = 0
        
        for attachment in attachments:
            filename = attachment.get('filename', '').lower()
            
            # Vérifier les extensions dangereuses
            for ext in self.dangerous_extensions:
                if filename.endswith(ext):
                    score += 30  # Très dangereux
            
            # Vérifier les noms suspects
            suspicious_names = ['invoice', 'facture', 'document', 'file', 'scan']
            for name in suspicious_names:
                if name in filename:
                    score += 5
        
        return min(score, 50)
    #le but : repérer les liens vers des sites malveillants
    def _extract_urls(self, text: str) -> list:
        """Extrait les URLs d'un texte"""
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        return re.findall(url_pattern, text)
    
    def _analyze_urls(self, urls: list) -> int:
        """Analyse les URLs"""
        score = 0
        
        for url in urls:
            try:
                parsed = urlparse(url if url.startswith('http') else f'http://{url}')
                domain = parsed.netloc
                
                # Vérifier les URL raccourcies
                shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd']
                if any(shortener in domain for shortener in shorteners):
                    score += 15
                
                # Vérifier les IP addresses directes
                if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                    score += 20
                    
            except:
                continue
        
        return min(score, 40)
    
    def _determine_threat(self, risk_score: int, threats_detected: list) -> Tuple[str, str]:
        """Détermine le niveau et type de menace"""
        
        # Déterminer le type de menace principal
        threat_type = 'NONE'
        if risk_score > 50:
            threat_type = 'PHISHING'
        elif risk_score > 30:
            threat_type = 'SPAM'
        elif risk_score > 20:
            threat_type = 'SUSPICIOUS'
        
        # Déterminer le niveau de menace
        if risk_score >= 70:
            threat_level = 'CRITICAL'
        elif risk_score >= 50:
            threat_level = 'HIGH'
        elif risk_score >= 30:
            threat_level = 'MEDIUM'
        elif risk_score >= 15:
            threat_level = 'LOW'
        else:
            threat_level = 'SAFE'
        
        return threat_level, threat_type