#!/usr/bin/env python3
"""
IDM MCP Server - Model Context Protocol server pro ARICOMA Identity Management
Umožňuje vyhledávání skupin a uživatelů v IDM přímo z Claude Desktop / Code
"""

import os
import sys
import requests
import warnings
import xml.etree.ElementTree as ET
from typing import Optional, Dict, List, Any
from mcp.server.fastmcp import FastMCP

# Suppress SSL warnings pro IDM API
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Inicializuj FastMCP server
mcp = FastMCP("IDM Server")

# IDM API konfigurace
IDM_ENDPOINT = os.getenv("IDM_ENDPOINT", "")
IDM_GUID_SYSTEM = os.getenv("IDM_GUID_SYSTEM", "")
IDM_LOGIN = os.getenv("IDM_LOGIN", "")
IDM_PASSWORD = os.getenv("IDM_PASSWORD", "")

# Default doménový kód pro vyhledávání (např. "ACME", "MYCORP"). Nech prázdné, pokud
# nechceš implicitně filtrovat podle domény.
IDM_DEFAULT_DOMAIN = os.getenv("IDM_DEFAULT_DOMAIN", "")

# Kód uživatelského atributu pro custom_attribute_2 — liší se podle tenanta v IDM.
# Konfigurovatelné kvůli generickému použití napříč organizacemi.
IDM_CUSTOM_ATTRIBUTE_2_CODE = os.getenv("IDM_CUSTOM_ATTRIBUTE_2_CODE", "AD_CUSTOM_ATTRIBUTE_2")


class IdmApiClient:
    """Client pro IDM SOAP API"""

    def __init__(self):
        self.endpoint = IDM_ENDPOINT
        self.guid_system = IDM_GUID_SYSTEM
        self.login = IDM_LOGIN
        self.password = IDM_PASSWORD
        self.session_guid: Optional[str] = None

    def _make_request(self, body: str, retry_on_auth_error: bool = True) -> ET.Element:
        """Provede SOAP request"""
        response = requests.post(
            self.endpoint,
            data=body,
            headers={"Content-Type": "application/xml"},  # Bez charset= podle PowerShell
            timeout=60,  # Zvýšený timeout
            verify=False,  # Disable SSL verification pro IDM API
        )

        # Zkontroluj response
        if response.status_code != 200:
            # Pokud je to 500 a obsahuje session error, zkus znovu přihlásit
            if response.status_code == 500 and retry_on_auth_error:
                error_text = response.text.lower()
                if 'session' in error_text or 'guid' in error_text or 'prihlaseni' in error_text:
                    sys.stderr.write("Session expired, re-authenticating...\n")
                    self.session_guid = None
                    self.login_to_idm()
                    # Zkus request znovu (ale už jen jednou)
                    return self._make_request(body, retry_on_auth_error=False)

            # Log full error response before raising
            sys.stderr.write(f"IDM API Error - Status: {response.status_code}\n")
            sys.stderr.write(f"Response body: {response.text}\n")
            raise Exception(f"IDM API returned {response.status_code}: {response.text}")

        # Parse XML response
        try:
            root = ET.fromstring(response.text)
        except ET.ParseError as e:
            sys.stderr.write(f"XML Parse Error: {e}\n")
            sys.stderr.write(f"Response text: {response.text[:500]}\n")
            raise Exception(f"Failed to parse XML response: {e}")

        # Zkontroluj, jestli response neobsahuje error
        for elem in root.iter():
            if elem.tag.endswith('errorMessage') or elem.tag.endswith('error'):
                error_msg = elem.text or "Unknown error"
                raise Exception(f"IDM API Error: {error_msg}")

        return root

    def _extract_text(self, root: ET.Element, tag: str) -> Optional[str]:
        """Extrahuje text z XML elementu"""
        # Hledej element bez namespace
        for elem in root.iter():
            if elem.tag.endswith(tag):
                return elem.text
        return None

    def _extract_all(self, root: ET.Element, tag: str) -> List[ET.Element]:
        """Extrahuje všechny elementy daného tagu"""
        result = []
        for elem in root.iter():
            if elem.tag.endswith(tag):
                result.append(elem)
        return result

    def login_to_idm(self) -> str:
        """Přihlášení do IDM"""
        sys.stderr.write(f"DEBUG login_to_idm: guid_system='{self.guid_system}', login='{self.login}', password_len={len(self.password)}\n")
        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:cz:autocont:idm:interface:external">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:loginToIdm>
                    <ExLoginRequest>
                        <guidSystem>{self.guid_system}</guidSystem>
                        <login>{self.login}</login>
                        <password>{self.password}</password>
                    </ExLoginRequest>
                </urn:loginToIdm>
            </soapenv:Body>
        </soapenv:Envelope>"""

        root = self._make_request(body, retry_on_auth_error=False)
        guid_session = self._extract_text(root, "guidSession")

        if not guid_session:
            raise Exception("Failed to get session GUID from IDM")

        self.session_guid = guid_session
        return guid_session

    def ensure_session(self) -> str:
        """Zajistí platnou session"""
        if not self.session_guid:
            self.login_to_idm()
        return self.session_guid

    def get_list_user_group(
        self,
        organization_code: Optional[str] = None,
        domain_code: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Získá seznam skupin"""
        session = self.ensure_session()

        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:cz:autocont:idm:interface:external">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:getListUserGroup>
                    <ExListUserGroupRequest>
                        <guidSystem>{self.guid_system}</guidSystem>
                        <guidSession>{session}</guidSession>"""

        if organization_code:
            body += f"<organizationCode>{organization_code}</organizationCode>"
        if domain_code:
            body += f"<domainCode>{domain_code}</domainCode>"
        if status:
            body += f"<status>{status}</status>"

        body += """</ExListUserGroupRequest>
                </urn:getListUserGroup>
            </soapenv:Body>
        </soapenv:Envelope>"""

        root = self._make_request(body)

        # Extrahuj skupiny
        groups = []
        for group_elem in self._extract_all(root, "UserGroup"):
            group = {
                "id": self._extract_text(group_elem, "id"),
                "code": self._extract_text(group_elem, "code"),
                "name": self._extract_text(group_elem, "name"),
                "domain": self._extract_text(group_elem, "domain"),
                "status": self._extract_text(group_elem, "status"),
                "description": self._extract_text(group_elem, "description"),
                "email": self._extract_text(group_elem, "email"),
            }
            groups.append(group)

        return {"count": len(groups), "groups": groups}

    def get_detail_user_group(
        self,
        id_user_group: Optional[str] = None,
        code: Optional[str] = None,
        name_user_group: Optional[str] = None,
        domain_code: Optional[str] = None,
        include_user_in_group: bool = True,
        user_status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Získá detail skupiny"""
        session = self.ensure_session()

        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:cz:autocont:idm:interface:external">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:getDetailUserGroup>
                    <ExDetailUserGroupRequest>
                        <guidSystem>{self.guid_system}</guidSystem>
                        <guidSession>{session}</guidSession>"""

        if id_user_group:
            body += f"<idUserGroup>{id_user_group}</idUserGroup>"
        if code:
            body += f"<code>{code}</code>"
        if name_user_group:
            body += f"<nameUserGroup>{name_user_group}</nameUserGroup>"
        if domain_code:
            body += f"<domainCode>{domain_code}</domainCode>"
        if include_user_in_group:
            body += "<includeUserInGroup>true</includeUserInGroup>"
        if user_status:
            body += f"<userStatus>{user_status}</userStatus>"

        body += """</ExDetailUserGroupRequest>
                </urn:getDetailUserGroup>
            </soapenv:Body>
        </soapenv:Envelope>"""

        root = self._make_request(body)

        # Extrahuj detail skupiny
        group = {
            "id": self._extract_text(root, "idRecord"),
            "code": self._extract_text(root, "code"),
            "name": self._extract_text(root, "name"),
            "domain": self._extract_text(root, "domain"),
            "description": self._extract_text(root, "description"),
            "email": self._extract_text(root, "email"),
            "status": self._extract_text(root, "status"),
            "groupType": self._extract_text(root, "groupType"),
            "groupScope": self._extract_text(root, "groupScope"),
        }

        # Extrahuj členy
        members = []
        for user_elem in self._extract_all(root, "User"):
            member = {
                "id": self._extract_text(user_elem, "id"),
                "login": self._extract_text(user_elem, "login"),
                "domain": self._extract_text(user_elem, "domain"),
                "firstName": self._extract_text(user_elem, "firstName"),
                "surname": self._extract_text(user_elem, "surname"),
                "email": self._extract_text(user_elem, "email"),
                "status": self._extract_text(user_elem, "status"),
            }
            members.append(member)

        return {"group": group, "members": members, "memberCount": len(members)}

    def get_list_user(
        self,
        organization_code: Optional[str] = None,
        domain_code: Optional[str] = None,
        status: Optional[str] = None,
        user_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Získá seznam uživatelů"""
        session = self.ensure_session()

        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:cz:autocont:idm:interface:external">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:getListUserV2>
                    <ExListUserRequest>
                        <guidSystem>{self.guid_system}</guidSystem>
                        <guidSession>{session}</guidSession>"""

        if organization_code:
            body += f"<organizationCode>{organization_code}</organizationCode>"
        if domain_code:
            body += f"<domainCode>{domain_code}</domainCode>"
        if status:
            body += f"<status>{status}</status>"
        if user_type:
            body += f"<userType>{user_type}</userType>"

        body += """</ExListUserRequest>
                </urn:getListUserV2>
            </soapenv:Body>
        </soapenv:Envelope>"""

        root = self._make_request(body)

        # Extrahuj uživatele
        users = []
        for user_elem in self._extract_all(root, "User"):
            user = {
                "id": self._extract_text(user_elem, "id"),
                "login": self._extract_text(user_elem, "login"),
                "domain": self._extract_text(user_elem, "domain"),
                "firstName": self._extract_text(user_elem, "firstName"),
                "surname": self._extract_text(user_elem, "surname"),
                "email": self._extract_text(user_elem, "email"),
                "status": self._extract_text(user_elem, "status"),
            }
            users.append(user)

        return {"count": len(users), "users": users}

    def get_detail_user(
        self,
        id_user: Optional[str] = None,
        login: Optional[str] = None,
        email: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Získá detail uživatele"""
        session = self.ensure_session()

        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:cz:autocont:idm:interface:external">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:getDetailUser>
                    <ExDetailUserRequest>
                        <guidSystem>{self.guid_system}</guidSystem>
                        <guidSession>{session}</guidSession>"""

        if id_user:
            body += f"<idUser>{id_user}</idUser>"
        if login:
            body += f"<login>{login}</login>"
        if email:
            body += f"<email>{email}</email>"
        if domain:
            body += f"<domain>{domain}</domain>"

        body += """</ExDetailUserRequest>
                </urn:getDetailUser>
            </soapenv:Body>
        </soapenv:Envelope>"""

        root = self._make_request(body)

        return {
            "id": self._extract_text(root, "id"),
            "login": self._extract_text(root, "login"),
            "domain": self._extract_text(root, "domain"),
            "firstName": self._extract_text(root, "firstName"),
            "surname": self._extract_text(root, "surname"),
            "email": self._extract_text(root, "email"),
            "status": self._extract_text(root, "status"),
            "organization": self._extract_text(root, "organization"),
            "orgUnit": self._extract_text(root, "orgUnit"),
        }

    def add_user_to_group(
        self,
        login: str,
        name_user_group: str,
        domain: Optional[str] = None,
    ) -> None:
        """Přidá uživatele do skupiny"""
        session = self.ensure_session()

        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:cz:autocont:idm:interface:external">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:addUserToUserGroup>
                    <ExAddUserToUserGroupRequest>
                        <guidSystem>{self.guid_system}</guidSystem>
                        <guidSession>{session}</guidSession>
                        <login>{login}</login>"""

        if domain:
            body += f"<domain>{domain}</domain>"

        body += f"""<nameUserGroup>{name_user_group}</nameUserGroup>
                    </ExAddUserToUserGroupRequest>
                </urn:addUserToUserGroup>
            </soapenv:Body>
        </soapenv:Envelope>"""

        self._make_request(body)

    def remove_user_from_group(
        self,
        login: str,
        name_user_group: str,
        domain: Optional[str] = None,
    ) -> None:
        """Odebere uživatele ze skupiny"""
        session = self.ensure_session()

        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:cz:autocont:idm:interface:external">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:removeUserFromUserGroup>
                    <ExRemoveUserFromUserGroupRequest>
                        <guidSystem>{self.guid_system}</guidSystem>
                        <guidSession>{session}</guidSession>
                        <login>{login}</login>"""

        if domain:
            body += f"<domain>{domain}</domain>"

        body += f"""<nameUserGroup>{name_user_group}</nameUserGroup>
                    </ExRemoveUserFromUserGroupRequest>
                </urn:removeUserFromUserGroup>
            </soapenv:Body>
        </soapenv:Envelope>"""

        self._make_request(body)

    def create_user_group(
        self,
        name: str,
        user_group_type: str,
        user_group_scope: Optional[str] = None,
        description: Optional[str] = None,
        info: Optional[str] = None,
        email: Optional[str] = None,
        denied_in_permission: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Vytvoří novou skupinu v IDM

        Args:
            name: Název nové skupiny
            user_group_type: Typ skupiny (APPLICATION_GROUP, AD_SECURITY, AD_DISTRIBUTION)
            user_group_scope: Rozsah skupiny (GLOBAL, LOCAL, UNIVERSAL) - typicky pro AD skupiny
            description: Popis skupiny
            info: Doplňující info
            email: Email skupiny
            denied_in_permission: Denied in permission flag
        """
        session = self.ensure_session()

        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:cz:autocont:idm:interface:external">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:createUserGroup>
                    <ExCreateUserGroupRequest>
                        <guidSystem>{self.guid_system}</guidSystem>
                        <guidSession>{session}</guidSession>
                        <name>{name}</name>
                        <userGroupType>{user_group_type}</userGroupType>"""

        if user_group_scope:
            body += f"<userGroupScope>{user_group_scope}</userGroupScope>"
        if description:
            body += f"<description>{description}</description>"
        if info:
            body += f"<info>{info}</info>"
        if email:
            body += f"<email>{email}</email>"
        if denied_in_permission:
            body += f"<deniedInPermission>{denied_in_permission}</deniedInPermission>"

        body += """</ExCreateUserGroupRequest>
                </urn:createUserGroup>
            </soapenv:Body>
        </soapenv:Envelope>"""

        root = self._make_request(body)

        return {
            "id": self._extract_text(root, "idRecord") or self._extract_text(root, "id"),
            "name": name,
        }

    def change_user_group(
        self,
        search_user_group_name: str,
        new_name: str,
        search_domain_code: str = IDM_DEFAULT_DOMAIN,
        user_group_type: Optional[str] = None,
        description: Optional[str] = None,
        user_group_scope: Optional[str] = None,
        info: Optional[str] = None,
        email: Optional[str] = None,
        status: Optional[str] = None,
    ) -> None:
        """Změní název skupiny a další atributy

        Funkce nejprve získá detail skupiny, aby zachovala současné hodnoty,
        pak provede změnu pouze specifikovaných polí.
        """
        session = self.ensure_session()

        # Nejprve získej detail skupiny pro zachování současných hodnot
        current_group = self.get_detail_user_group(
            name_user_group=search_user_group_name,
            domain_code=search_domain_code,
            include_user_in_group=False,
        )

        group_info = current_group['group']

        # Použij současné hodnoty pokud nejsou specifikované nové
        # Ošetři None hodnoty - pokud je pole None nebo prázdné, neposílej ho
        description = description if description is not None else (group_info.get('description') or '')
        email = email if email is not None else (group_info.get('email') or '')
        info = info if info is not None else ''  # info není v API response, použij prázdný string
        status = status if status is not None else (group_info.get('status') or 'ACTIVE')
        user_group_type = user_group_type if user_group_type is not None else (group_info.get('groupType') or 'APPLICATION_GROUP')
        user_group_scope = user_group_scope if user_group_scope is not None else (group_info.get('groupScope') or '')

        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:cz:autocont:idm:interface:external">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:changeUserGroup>
                    <ExChangeUserGroupRequest>
                        <guidSystem>{self.guid_system}</guidSystem>
                        <guidSession>{session}</guidSession>
                        <searchUserGroupName>{search_user_group_name}</searchUserGroupName>
                        <searchDomainCode>{search_domain_code}</searchDomainCode>
                        <name>{new_name}</name>
                        <userGroupType>{user_group_type}</userGroupType>"""

        if user_group_scope:
            body += f"<userGroupScope>{user_group_scope}</userGroupScope>"

        # Pouze přidej pole pokud nejsou prázdné
        if description:
            body += f"<description>{description}</description>"
        if info:
            body += f"<info>{info}</info>"
        if email:
            body += f"<email>{email}</email>"

        body += f"""<status>{status}</status>
                    </ExChangeUserGroupRequest>
                </urn:changeUserGroup>
            </soapenv:Body>
        </soapenv:Envelope>"""

        self._make_request(body)

    def save_user_attribute_to_entity(
        self,
        entity_code: str,
        id_object: str,
        user_attribute_code: str,
        user_attribute_value: str,
    ) -> None:
        """Uloží uživatelský atribut k entitě (např. skupině)

        Args:
            entity_code: Kód entity (např. "T_USER_GROUP" pro skupiny)
            id_object: ID objektu (např. ID skupiny)
            user_attribute_code: Kód atributu (např. "AD_CUSTOM_ATTRIBUTE_2")
            user_attribute_value: Hodnota atributu (např. "resource")
        """
        session = self.ensure_session()

        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:cz:autocont:idm:interface:external">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:saveUserAttributeToEntity>
                    <ExSaveUserAttributeToEntityRequest>
                        <guidSystem>{self.guid_system}</guidSystem>
                        <guidSession>{session}</guidSession>
                        <entityCode>{entity_code}</entityCode>
                        <idObject>{id_object}</idObject>
                        <userAttributeCode>{user_attribute_code}</userAttributeCode>
                        <userAttributeValue>{user_attribute_value}</userAttributeValue>
                    </ExSaveUserAttributeToEntityRequest>
                </urn:saveUserAttributeToEntity>
            </soapenv:Body>
        </soapenv:Envelope>"""

        self._make_request(body)

    def remove_user_group_parent(
        self,
        user_group_name: str,
        parent_user_group_name: str,
        domain_code: Optional[str] = None,
        user_group_id: Optional[str] = None,
        user_group_code: Optional[str] = None,
        parent_user_group_id: Optional[str] = None,
        parent_user_group_code: Optional[str] = None,
    ) -> None:
        """Odebere parent skupinu z child skupiny

        Args:
            user_group_name: Název child skupiny
            parent_user_group_name: Název parent skupiny k odebrání
            domain_code: Kód domény (optional)
            user_group_id: ID child skupiny (optional)
            user_group_code: Kód child skupiny (optional)
            parent_user_group_id: ID parent skupiny (optional)
            parent_user_group_code: Kód parent skupiny (optional)
        """
        session = self.ensure_session()

        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:cz:autocont:idm:interface:external">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:removeUserGroupParent>
                    <ExRemoveUserGroupParentRequest>
                        <guidSystem>{self.guid_system}</guidSystem>
                        <guidSession>{session}</guidSession>"""

        if user_group_id:
            body += f"<userGroupId>{user_group_id}</userGroupId>"
        if user_group_code:
            body += f"<userGroupCode>{user_group_code}</userGroupCode>"
        if user_group_name:
            body += f"<userGroupName>{user_group_name}</userGroupName>"
        if domain_code:
            body += f"<domainCode>{domain_code}</domainCode>"
        if parent_user_group_id:
            body += f"<parentUserGroupId>{parent_user_group_id}</parentUserGroupId>"
        if parent_user_group_code:
            body += f"<parentUserGroupCode>{parent_user_group_code}</parentUserGroupCode>"
        if parent_user_group_name:
            body += f"<parentUserGroupName>{parent_user_group_name}</parentUserGroupName>"

        body += """</ExRemoveUserGroupParentRequest>
                </urn:removeUserGroupParent>
            </soapenv:Body>
        </soapenv:Envelope>"""

        self._make_request(body)

    def add_user_group_parent(
        self,
        user_group_name: str,
        parent_user_group_name: str,
        domain_code: Optional[str] = None,
        user_group_id: Optional[str] = None,
        user_group_code: Optional[str] = None,
        parent_user_group_id: Optional[str] = None,
        parent_user_group_code: Optional[str] = None,
    ) -> None:
        """Přidá parent skupinu k child skupině (parent record v IDM)

        Args:
            user_group_name: Název child skupiny (skupina, které přidáváme parent)
            parent_user_group_name: Název parent skupiny (skupina, která se stane parentem)
            domain_code: Kód domény (optional)
            user_group_id: ID child skupiny (optional, alternativa k user_group_name)
            user_group_code: Kód child skupiny (optional)
            parent_user_group_id: ID parent skupiny (optional, alternativa k parent_user_group_name)
            parent_user_group_code: Kód parent skupiny (optional)
        """
        session = self.ensure_session()

        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:cz:autocont:idm:interface:external">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:addUserGroupParent>
                    <ExAddUserGroupParentRequest>
                        <guidSystem>{self.guid_system}</guidSystem>
                        <guidSession>{session}</guidSession>"""

        if user_group_id:
            body += f"<userGroupId>{user_group_id}</userGroupId>"
        if user_group_code:
            body += f"<userGroupCode>{user_group_code}</userGroupCode>"
        if user_group_name:
            body += f"<userGroupName>{user_group_name}</userGroupName>"
        if domain_code:
            body += f"<domainCode>{domain_code}</domainCode>"
        if parent_user_group_id:
            body += f"<parentUserGroupId>{parent_user_group_id}</parentUserGroupId>"
        if parent_user_group_code:
            body += f"<parentUserGroupCode>{parent_user_group_code}</parentUserGroupCode>"
        if parent_user_group_name:
            body += f"<parentUserGroupName>{parent_user_group_name}</parentUserGroupName>"

        body += """</ExAddUserGroupParentRequest>
                </urn:addUserGroupParent>
            </soapenv:Body>
        </soapenv:Envelope>"""

        self._make_request(body)


# Vytvoř globální client
idm_client = IdmApiClient()


# === MCP Tools ===


@mcp.tool()
def idm_search_groups(
    name_contains: str = None,
    organization_code: str = None,
    domain_code: str = IDM_DEFAULT_DOMAIN,
    status: str = None,
    max_results: int = 100,
) -> Dict[str, Any]:
    """
    Vyhledá skupiny v IDM podle různých kritérií

    ⚠️ DŮLEŽITÉ UPOZORNĚNÍ:
    - Pokud hledáš KONKRÉTNÍ skupinu (znáš přesný název), použij idm_get_group_detail!
    - idm_get_group_detail je 100x rychlejší než search
    - Tento tool načítá VŠECHNY skupiny a pak filtruje - může být VELMI POMALÝ!
    - VŽDY specifikuj name_contains pro rychlejší hledání!

    Args:
        name_contains: Část názvu skupiny k vyhledání (SILNĚ DOPORUČENO!)
        organization_code: Kód organizace (optional)
        domain_code: Kód domény (default: IDM_DEFAULT_DOMAIN env var, ostatní domény: ask user)
        status: Status skupiny - ACTIVE nebo INACTIVE (optional)
        max_results: Maximální počet vrácených výsledků (default: 100)

    Returns:
        Slovník se seznamem skupin a jejich počtem
    """
    # Načti skupiny z IDM
    result = idm_client.get_list_user_group(organization_code, domain_code, status)

    groups = result['groups']

    # Pokud je zadán name_contains, filtruj lokálně
    if name_contains:
        name_lower = name_contains.lower()
        groups = [
            g for g in groups
            if name_lower in (g['name'] or '').lower()
        ]

    # Omezte výsledky
    if len(groups) > max_results:
        groups = groups[:max_results]
        return {
            "count": len(groups),
            "groups": groups,
            "warning": f"Zobrazeno pouze prvních {max_results} z celkového počtu. Upřesni hledání pomocí name_contains nebo použij idm_get_group_detail pro konkrétní skupinu."
        }

    return {"count": len(groups), "groups": groups}


@mcp.tool()
def idm_get_group_detail(
    name_user_group: str = None,
    domain_code: str = IDM_DEFAULT_DOMAIN,
    id_user_group: str = None,
    include_members: bool = True,
    user_status: str = None,
) -> Dict[str, Any]:
    """
    Získá detail konkrétní skupiny včetně členů

    🎯 NEJRYCHLEJŠÍ způsob jak získat info o skupině!
    Použij tento tool místo idm_search_groups když znáš přesný název skupiny.

    Args:
        name_user_group: Název skupiny (vyžadováno pokud není id_user_group)
        domain_code: Kód domény (default: IDM_DEFAULT_DOMAIN env var, doporučeno vždy specifikovat)
        id_user_group: ID skupiny (alternativa k name_user_group)
        include_members: Zahrnout seznam členů (default: True)
        user_status: Filtr statusu uživatelů - ACTIVE nebo INACTIVE (optional)

    Returns:
        Slovník s detailem skupiny a seznamem členů
    """
    return idm_client.get_detail_user_group(
        id_user_group=id_user_group,
        name_user_group=name_user_group,
        domain_code=domain_code,
        include_user_in_group=include_members,
        user_status=user_status,
    )


@mcp.tool()
def idm_search_users(
    organization_code: str = None,
    domain_code: str = IDM_DEFAULT_DOMAIN,
    status: str = None,
    user_type: str = None,
) -> Dict[str, Any]:
    """
    Vyhledá uživatele v IDM

    ⚠️ VAROVÁNÍ: Může být pomalé při načítání všech uživatelů!
    Doporučeno specifikovat status nebo organization_code.

    Args:
        organization_code: Kód organizace (optional)
        domain_code: Kód domény (default: IDM_DEFAULT_DOMAIN env var)
        status: Status uživatele - ACTIVE nebo INACTIVE (doporučeno!)
        user_type: Typ uživatele (optional)

    Returns:
        Slovník se seznamem uživatelů
    """
    return idm_client.get_list_user(organization_code, domain_code, status, user_type)


@mcp.tool()
def idm_get_user_detail(
    login: str = None,
    domain: str = IDM_DEFAULT_DOMAIN,
    email: str = None,
) -> Dict[str, Any]:
    """
    Získá detail konkrétního uživatele

    Args:
        login: Login uživatele (vyžadováno pokud není email)
        domain: Doména uživatele (default: IDM_DEFAULT_DOMAIN env var, doporučeno vždy specifikovat)
        email: Email uživatele (alternativa k login)

    Returns:
        Slovník s detailem uživatele
    """
    return idm_client.get_detail_user(login=login, email=email, domain=domain)


@mcp.tool()
def idm_add_user_to_group(
    login: str,
    name_user_group: str,
    domain: str = None,
) -> str:
    """
    Přidá uživatele do skupiny

    Args:
        login: Login uživatele (povinné)
        name_user_group: Název skupiny (povinné)
        domain: Doména uživatele (optional, doporučeno)

    Returns:
        Potvrzovací zpráva
    """
    idm_client.add_user_to_group(login, name_user_group, domain)
    return f"Uživatel {login} byl přidán do skupiny {name_user_group}"


@mcp.tool()
def idm_remove_user_from_group(
    login: str,
    name_user_group: str,
    domain: str = None,
) -> str:
    """
    Odebere uživatele ze skupiny

    Args:
        login: Login uživatele (povinné)
        name_user_group: Název skupiny (povinné)
        domain: Doména uživatele (optional, doporučeno)

    Returns:
        Potvrzovací zpráva
    """
    idm_client.remove_user_from_group(login, name_user_group, domain)
    return f"Uživatel {login} byl odebrán ze skupiny {name_user_group}"


@mcp.tool()
def idm_rename_group(
    current_name: str,
    new_name: str,
    domain_code: str = IDM_DEFAULT_DOMAIN,
    user_group_type: str = None,
    user_group_scope: str = None,
    description: str = None,
    info: str = None,
    email: str = None,
    status: str = None,
) -> str:
    """
    Přejmenuje skupinu v IDM

    ⚠️ DŮLEŽITÉ: Tato operace změní název skupiny!
    Pokud nejsou specifikované description, info, email, status nebo user_group_type, zachovají se současné hodnoty.

    Args:
        current_name: Současný název skupiny (povinné)
        new_name: Nový název skupiny (povinné)
        domain_code: Kód domény (default: IDM_DEFAULT_DOMAIN env var)
        user_group_type: Typ skupiny (optional, zachová se současný pokud není specifikováno)
            Možné hodnoty:
            - "APPLICATION_GROUP" - Aplikační skupina (No AD)
            - "AD_SECURITY" - AD Security skupina
            - "AD_DISTRIBUTION" - AD Distribution skupina
        user_group_scope: Rozsah skupiny (optional, zachová se současný pokud není specifikováno)
            Možné hodnoty:
            - "GLOBAL" - Globální
            - "LOCAL" - Lokální (Domain Local)
            - "UNIVERSAL" - Univerzální
        description: Nový popis (optional, zachová se současný pokud není specifikováno)
        info: Nové info (optional, zachová se současné pokud není specifikováno)
        email: Nový email (optional, zachová se současný pokud není specifikováno)
        status: Nový status (optional, zachová se současný pokud není specifikováno)

    Returns:
        Potvrzovací zpráva
    """
    idm_client.change_user_group(
        search_user_group_name=current_name,
        new_name=new_name,
        search_domain_code=domain_code,
        user_group_type=user_group_type,
        user_group_scope=user_group_scope,
        description=description,
        info=info,
        email=email,
        status=status,
    )
    result_msg = f"Skupina '{current_name}' byla přejmenována na '{new_name}'"
    if user_group_type:
        result_msg += f", typ: {user_group_type}"
    if user_group_scope:
        result_msg += f", scope: {user_group_scope}"
    return result_msg


@mcp.tool()
def idm_add_group_parent(
    child_group_name: str,
    parent_group_name: str,
    domain_code: str = IDM_DEFAULT_DOMAIN,
) -> str:
    """
    Přidá parent skupinu k child skupině (vytvoří parent record v IDM)

    Tato funkce umožňuje vytvořit hierarchickou vazbu mezi skupinami.
    Child skupina "zdědí" členy z parent skupiny.

    Příklad použití:
    - Child: "G_DP_DEVELOPMENT_Specialist" (kompetence)
    - Parent: "d_special_heads" (resource skupina)
    → Kompetence získá přístup k resource skupině

    Args:
        child_group_name: Název child skupiny (skupina, které přidáváme parent)
        parent_group_name: Název parent skupiny (resource skupina, která se přidává jako parent record)
        domain_code: Kód domény (default: IDM_DEFAULT_DOMAIN env var)

    Returns:
        Potvrzovací zpráva
    """
    idm_client.add_user_group_parent(
        user_group_name=child_group_name,
        parent_user_group_name=parent_group_name,
        domain_code=domain_code,
    )
    return f"Parent skupina '{parent_group_name}' byla přidána ke skupině '{child_group_name}' v doméně {domain_code}"


@mcp.tool()
def idm_remove_group_parent(
    child_group_name: str,
    parent_group_name: str,
    domain_code: str = IDM_DEFAULT_DOMAIN,
) -> str:
    """
    Odebere parent skupinu z child skupiny v IDM

    Args:
        child_group_name: Název child skupiny (skupina, ze které odebíráme parent)
        parent_group_name: Název parent skupiny k odebrání
        domain_code: Kód domény (default: IDM_DEFAULT_DOMAIN env var)

    Returns:
        Potvrzovací zpráva
    """
    idm_client.remove_user_group_parent(
        user_group_name=child_group_name,
        parent_user_group_name=parent_group_name,
        domain_code=domain_code,
    )
    return f"Parent skupina '{parent_group_name}' byla odebrána ze skupiny '{child_group_name}' v doméně {domain_code}"


@mcp.tool()
def idm_set_group_attribute(
    group_name: str,
    attribute_code: str,
    attribute_value: str,
    domain_code: str = IDM_DEFAULT_DOMAIN,
) -> str:
    """
    Nastaví uživatelský atribut pro skupinu v IDM

    Tato funkce umožňuje nastavit custom atributy jako customAttribute2.

    Args:
        group_name: Název skupiny (povinné)
        attribute_code: Kód atributu (povinné)
            Běžné hodnoty:
            - "AD_CUSTOM_ATTRIBUTE_2" - customAttribute2 (např. "resource", "competence")
        attribute_value: Hodnota atributu (povinné)
            Pro AD_CUSTOM_ATTRIBUTE_2:
            - "resource" - resource skupina
            - "competence" - kompetenční skupina
        domain_code: Kód domény (default: IDM_DEFAULT_DOMAIN env var)

    Returns:
        Potvrzovací zpráva
    """
    # Nejprve získej ID skupiny
    group_detail = idm_client.get_detail_user_group(
        name_user_group=group_name,
        domain_code=domain_code,
        include_user_in_group=False,
    )

    group_id = group_detail['group'].get('id')
    if not group_id:
        raise Exception(f"Skupina '{group_name}' nebyla nalezena nebo nemá ID")

    # Nastav atribut
    idm_client.save_user_attribute_to_entity(
        entity_code="T_USER_GROUP",
        id_object=group_id,
        user_attribute_code=attribute_code,
        user_attribute_value=attribute_value,
    )

    return f"Atribut '{attribute_code}' = '{attribute_value}' byl nastaven pro skupinu '{group_name}'"


@mcp.tool()
def idm_create_group(
    name: str,
    group_type: str = "APPLICATION_GROUP",
    group_scope: str = None,
    custom_attribute_2: str = None,
    description: str = None,
    info: str = None,
    email: str = None,
    denied_in_permission: str = None,
    domain_code: str = IDM_DEFAULT_DOMAIN,
) -> str:
    """
    Vytvoří novou skupinu v IDM

    ⚠️ DŮLEŽITÉ: Tato operace vytvoří novou skupinu v IDM!
    Pro AD skupiny (AD_SECURITY, AD_DISTRIBUTION) je doporučeno specifikovat group_scope.

    Pokud je zadán custom_attribute_2, nastaví se customAttribute2 hned po vytvoření
    skupiny (provede se interně jako druhé volání saveUserAttributeToEntity).

    Args:
        name: Název nové skupiny (povinné)
        group_type: Typ skupiny (default: "APPLICATION_GROUP")
            Možné hodnoty:
            - "NO_AD" nebo "APPLICATION_GROUP" - Aplikační skupina bez AD
            - "AD_SECURITY" - AD Security skupina
            - "AD_DISTRIBUTION" - AD Distribution skupina
        group_scope: Rozsah skupiny (optional, doporučeno pro AD skupiny)
            Možné hodnoty:
            - "GLOBAL" - Globální
            - "LOCAL" nebo "DOMAIN_LOCAL" - Lokální (Domain Local)
            - "UNIVERSAL" - Univerzální
        custom_attribute_2: Hodnota pro customAttribute2 (optional)
            Běžné hodnoty: "resource", "competence"
        description: Popis skupiny (optional)
        info: Doplňující info (optional)
        email: Email skupiny (optional)
        denied_in_permission: Denied in permission flag (optional)
        domain_code: Kód domény pro dohledání ID nové skupiny při nastavování
            custom_attribute_2 (default: IDM_DEFAULT_DOMAIN env var)

    Returns:
        Potvrzovací zpráva s ID nově vytvořené skupiny a případně nastaveným atributem
    """
    # Mapování user-friendly názvů na API hodnoty (stejné jako v idm_change_group)
    type_mapping = {
        "NO_AD": "APPLICATION_GROUP",
        "AD_SECURITY": "AD_SECURITY",
        "AD SECURITY": "AD_SECURITY",
        "AD_DISTRIBUTION": "AD_DISTRIBUTION",
        "AD DISTRIBUTION": "AD_DISTRIBUTION",
        "APPLICATION_GROUP": "APPLICATION_GROUP",
    }

    scope_mapping = {
        "GLOBAL": "GLOBAL",
        "LOCAL": "LOCAL",
        "DOMAIN_LOCAL": "LOCAL",
        "DOMAIN LOCAL": "LOCAL",
        "UNIVERSAL": "UNIVERSAL",
    }

    api_group_type = type_mapping.get(group_type.upper(), group_type)
    api_group_scope = None
    if group_scope:
        api_group_scope = scope_mapping.get(group_scope.upper(), group_scope)

    result = idm_client.create_user_group(
        name=name,
        user_group_type=api_group_type,
        user_group_scope=api_group_scope,
        description=description,
        info=info,
        email=email,
        denied_in_permission=denied_in_permission,
    )

    msg = f"Skupina '{name}' byla vytvořena (typ: {api_group_type}"
    if api_group_scope:
        msg += f", scope: {api_group_scope}"
    msg += ")"

    # Pokud createUserGroup nevrátil ID, dohledej ho podle názvu
    group_id = result.get("id")
    if not group_id and custom_attribute_2:
        try:
            group_detail = idm_client.get_detail_user_group(
                name_user_group=name,
                domain_code=domain_code,
                include_user_in_group=False,
            )
            group_id = group_detail['group'].get('id')
        except Exception:
            group_id = None

    if group_id:
        msg += f", ID: {group_id}"

    # Nastav customAttribute2, pokud byl zadán
    if custom_attribute_2:
        if group_id:
            idm_client.save_user_attribute_to_entity(
                entity_code="T_USER_GROUP",
                id_object=group_id,
                user_attribute_code=IDM_CUSTOM_ATTRIBUTE_2_CODE,
                user_attribute_value=custom_attribute_2,
            )
            msg += f", customAttribute2: {custom_attribute_2}"
        else:
            msg += f" ⚠️ customAttribute2='{custom_attribute_2}' nebylo nastaveno - skupina nemá ID"

    return msg


@mcp.tool()
def idm_change_group(
    group_name: str,
    new_name: str = None,
    group_type: str = None,
    group_scope: str = None,
    custom_attribute_2: str = None,
    description: str = None,
    info: str = None,
    email: str = None,
    status: str = None,
    domain_code: str = IDM_DEFAULT_DOMAIN,
) -> str:
    """
    Změní vlastnosti skupiny v IDM (název, typ, scope, custom atributy)

    Toto je hlavní tool pro změnu skupin. Umožňuje změnit více vlastností najednou.

    Args:
        group_name: Současný název skupiny (povinné)
        new_name: Nový název skupiny (optional, pokud není zadáno, název se nezmění)
        group_type: Typ skupiny (optional)
            Možné hodnoty:
            - "NO_AD" nebo "APPLICATION_GROUP" - Aplikační skupina bez AD
            - "AD_SECURITY" - AD Security skupina
            - "AD_DISTRIBUTION" - AD Distribution skupina
        group_scope: Rozsah skupiny (optional)
            Možné hodnoty:
            - "GLOBAL" - Globální
            - "LOCAL" - Lokální (Domain Local)
            - "UNIVERSAL" - Univerzální
        custom_attribute_2: Hodnota pro customAttribute2 (optional)
            Běžné hodnoty: "resource", "competence"
        description: Nový popis (optional)
        info: Nové info (optional)
        email: Nový email (optional)
        status: Nový status - "ACTIVE" nebo "INACTIVE" (optional)
        domain_code: Kód domény (default: IDM_DEFAULT_DOMAIN env var)

    Returns:
        Potvrzovací zpráva se všemi provedenými změnami
    """
    changes = []

    # Mapování user-friendly názvů na API hodnoty
    type_mapping = {
        "NO_AD": "APPLICATION_GROUP",
        "AD_SECURITY": "AD_SECURITY",
        "AD SECURITY": "AD_SECURITY",
        "AD_DISTRIBUTION": "AD_DISTRIBUTION",
        "AD DISTRIBUTION": "AD_DISTRIBUTION",
        "APPLICATION_GROUP": "APPLICATION_GROUP",
    }

    scope_mapping = {
        "GLOBAL": "GLOBAL",
        "LOCAL": "LOCAL",
        "DOMAIN_LOCAL": "LOCAL",
        "DOMAIN LOCAL": "LOCAL",
        "UNIVERSAL": "UNIVERSAL",
    }

    # Převeď user-friendly hodnoty na API hodnoty
    api_group_type = None
    if group_type:
        api_group_type = type_mapping.get(group_type.upper(), group_type)
        changes.append(f"typ: {api_group_type}")

    api_group_scope = None
    if group_scope:
        api_group_scope = scope_mapping.get(group_scope.upper(), group_scope)
        changes.append(f"scope: {api_group_scope}")

    # Pokud se mění název nebo jiné základní vlastnosti, zavolej changeUserGroup
    effective_new_name = new_name if new_name else group_name

    if new_name:
        changes.append(f"název: {group_name} → {new_name}")

    if description:
        changes.append(f"popis: {description}")

    # Vždy zavolej changeUserGroup (i když jen pro zachování konzistence)
    idm_client.change_user_group(
        search_user_group_name=group_name,
        new_name=effective_new_name,
        search_domain_code=domain_code,
        user_group_type=api_group_type,
        user_group_scope=api_group_scope,
        description=description,
        info=info,
        email=email,
        status=status,
    )

    # Pokud se mění custom_attribute_2, zavolej saveUserAttributeToEntity
    if custom_attribute_2:
        # Získej ID skupiny (použij nový název pokud byl změněn)
        group_detail = idm_client.get_detail_user_group(
            name_user_group=effective_new_name,
            domain_code=domain_code,
            include_user_in_group=False,
        )

        group_id = group_detail['group'].get('id')
        if group_id:
            idm_client.save_user_attribute_to_entity(
                entity_code="T_USER_GROUP",
                id_object=group_id,
                user_attribute_code=IDM_CUSTOM_ATTRIBUTE_2_CODE,
                user_attribute_value=custom_attribute_2,
            )
            changes.append(f"customAttribute2: {custom_attribute_2}")
        else:
            changes.append(f"⚠️ customAttribute2 nebylo nastaveno - skupina nemá ID")

    if not changes:
        return f"Skupina '{group_name}' - žádné změny nebyly specifikovány"

    return f"Skupina '{group_name}' byla upravena: {', '.join(changes)}"


# Spusť server
if __name__ == "__main__":
    # Zkontroluj credentials
    if not all([IDM_GUID_SYSTEM, IDM_LOGIN, IDM_PASSWORD]):
        sys.stderr.write("Error: IDM credentials not configured!\n")
        sys.stderr.write("Please set: IDM_GUID_SYSTEM, IDM_LOGIN, IDM_PASSWORD\n")
        exit(1)

    # Spusť server (přihlášení se provede automaticky při prvním volání)
    mcp.run()