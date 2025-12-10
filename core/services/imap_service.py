# core/services/imap_service.py
import imaplib
import email
from email.header import decode_header
import ssl
from datetime import datetime, timedelta
import re
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)

class IMAPService:
    """Service pour interagir avec les serveurs IMAP"""
    
    def __init__(self, server: str, port: int, username: str, password: str, use_ssl: bool = True):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.connection = None
        
    def connect(self) -> bool:
        """Établir la connexion IMAP"""
        try:
            logger.info(f"🔗 Tentative de connexion à {self.server}:{self.port}...")
            
            if self.use_ssl:
                self.connection = imaplib.IMAP4_SSL(self.server, self.port)
            else:
                self.connection = imaplib.IMAP4(self.server, self.port)
            
            logger.info(f"🔐 Authentification avec {self.username}...")
            self.connection.login(self.username, self.password)
            
            logger.info("✅ Connexion IMAP réussie!")
            return True
            
        except imaplib.IMAP4.error as e:
            error_msg = str(e)
            if 'AUTHENTICATIONFAILED' in error_msg:
                logger.error("❌ ERREUR: Identifiants incorrects")
                logger.error("ℹ️  Pour Gmail, utilise un mot de passe d'application:")
                logger.error("   1. Active la validation en 2 étapes")
                logger.error("   2. Génère un mot de passe d'application")
                logger.error("   3. Utilise ce mot de passe de 16 caractères")
            elif 'Too many arguments' in error_msg:
                logger.error("❌ ERREUR: Format d'identifiants incorrect")
                logger.error("ℹ️  Pour Gmail, utilise juste l'email comme username")
            else:
                logger.error(f"❌ ERREUR IMAP: {error_msg}")
            return False
        except Exception as e:
            logger.error(f"❌ ERREUR: {type(e).__name__}: {e}")
            return False
    
    def disconnect(self):
        """Fermer la connexion"""
        if self.connection:
            try:
                self.connection.logout()
                logger.info("Déconnexion IMAP réussie")
            except:
                pass
    
    def fetch_emails(self, limit: int = 50, since_days: int = 7) -> List[Dict]:
        """Récupérer les emails récents"""
        if not self.connection:
            if not self.connect():
                return []
        
        try:
            # Sélectionner la boîte de réception
            self.connection.select('INBOX')
            
            # Calculer la date depuis laquelle récupérer les emails
            since_date = (datetime.now() - timedelta(days=since_days)).strftime("%d-%b-%Y")
            
            # Rechercher les emails non lus ou récents
            status, messages = self.connection.search(
                None, 
                f'(SINCE "{since_date}")',
            )
            
            if status != 'OK':
                logger.warning("Aucun email trouvé")
                return []
            
            email_ids = messages[0].split()
            
            # Limiter le nombre d'emails
            if limit > 0:
                email_ids = email_ids[-limit:]  # Les plus récents
            
            emails = []
            
            for email_id in email_ids:
                try:
                    # Récupérer l'email complet
                    status, msg_data = self.connection.fetch(email_id, '(RFC822)')
                    
                    if status != 'OK':
                        continue
                    
                    # Parser l'email
                    email_message = email.message_from_bytes(msg_data[0][1])
                    parsed_email = self._parse_email(email_message, email_id)
                    
                    if parsed_email:
                        emails.append(parsed_email)
                        
                except Exception as e:
                    logger.error(f"Erreur lors du parsing de l'email {email_id}: {e}")
                    continue
            
            return emails
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des emails: {e}")
            return []
    
    def _parse_email(self, email_message, email_id) -> Optional[Dict]:
        """Parser un email en dictionnaire"""
        try:
            # Décoder le sujet
            subject = self._decode_header(email_message.get('Subject', ''))
            
            # Décoder l'expéditeur
            from_header = email_message.get('From', '')
            sender_email = self._extract_email(from_header)
            sender_name = self._extract_name(from_header)
            
            # Date de réception
            date_str = email_message.get('Date', '')
            received_date = self._parse_email_date(date_str)
            
            # Récupérer le corps
            body_text, body_html = self._extract_body(email_message)
            
            # Pièces jointes
            attachments = self._extract_attachments(email_message)
            
            # Construire l'objet email
            parsed_email = {
                'uid': email_id.decode() if isinstance(email_id, bytes) else str(email_id),
                'message_id': email_message.get('Message-ID', ''),
                'sender': sender_email,
                'sender_name': sender_name,
                'recipients': email_message.get('To', ''),
                'subject': subject,
                'received_date': received_date,
                'body_text': body_text[:10000],  # Limiter la taille
                'body_html': body_html[:20000],  # Limiter la taille
                'attachments': attachments,
                'has_attachments': len(attachments) > 0,
                'size': len(email_message.as_bytes()),
                'headers': dict(email_message.items()),
            }
            
            return parsed_email
            
        except Exception as e:
            logger.error(f"Erreur de parsing: {e}")
            return None
    
    def _decode_header(self, header):
        """Décoder un en-tête email"""
        if not header:
            return ""
        
        try:
            decoded_parts = decode_header(header)
            decoded_str = ""
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_str += part.decode(encoding)
                    else:
                        decoded_str += part.decode('utf-8', 'ignore')
                else:
                    decoded_str += part
            
            return decoded_str
        except:
            return str(header)
    
    def _extract_email(self, from_header):
        """Extraire l'email d'un en-tête From"""
        try:
            # Chercher un email dans l'en-tête
            match = re.search(r'<([^>]+)>', from_header)
            if match:
                return match.group(1).strip()
            
            # Sinon, chercher directement un email
            match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', from_header)
            if match:
                return match.group(0).strip()
            
            return from_header.strip()
        except:
            return from_header or "unknown@unknown.com"
    
    def _extract_name(self, from_header):
        """Extraire le nom de l'expéditeur"""
        try:
            # Si format: "Nom <email@domain.com>"
            match = re.search(r'^"?([^"<]+)"?\s*<', from_header)
            if match:
                return match.group(1).strip()
            
            return ""
        except:
            return ""
    
    def _parse_email_date(self, date_str):
        """Parser la date d'un email"""
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_str)
        except:
            return datetime.now()
    
    def _extract_body(self, email_message):
        """Extraire le corps texte et HTML d'un email"""
        body_text = ""
        body_html = ""
        
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                # Ignorer les pièces jointes
                if "attachment" in content_disposition:
                    continue
                
                if content_type == "text/plain":
                    try:
                        body = part.get_payload(decode=True)
                        if body:
                            body_text += body.decode('utf-8', 'ignore')
                    except:
                        pass
                
                elif content_type == "text/html":
                    try:
                        body = part.get_payload(decode=True)
                        if body:
                            body_html += body.decode('utf-8', 'ignore')
                    except:
                        pass
        else:
            # Email non-multipart
            content_type = email_message.get_content_type()
            body = email_message.get_payload(decode=True)
            
            if body:
                try:
                    if content_type == "text/plain":
                        body_text = body.decode('utf-8', 'ignore')
                    elif content_type == "text/html":
                        body_html = body.decode('utf-8', 'ignore')
                except:
                    pass
        
        return body_text, body_html
    
    def _extract_attachments(self, email_message):
        """Extraire les informations sur les pièces jointes"""
        attachments = []
        
        if email_message.is_multipart():
            for part in email_message.walk():
                content_disposition = str(part.get("Content-Disposition"))
                
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        # Décoder le nom de fichier
                        filename = self._decode_header(filename)
                        
                        attachments.append({
                            'filename': filename,
                            'content_type': part.get_content_type(),
                            'size': len(part.get_payload(decode=True)) if part.get_payload() else 0,
                        })
        
        return attachments