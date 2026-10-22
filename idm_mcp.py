#!/usr/bin/env python3
"""
IDM MCP Server - Model Context Protocol server for ARICOMA Identity Management
Enables searching groups and users in IDM directly from Claude Desktop / Code
"""

import os
import sys
import getpass
import keyring
import keyring.errors
import requests
import warnings
import xml.etree.ElementTree as ET
from typing import Optional, Dict, List, Any
from mcp.server.fastmcp import FastMCP

# Suppress SSL warnings for the IDM API
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Initialize the FastMCP server
mcp = FastMCP("IDM Server")

# IDM API configuration
IDM_ENDPOINT = os.getenv("IDM_ENDPOINT", "")
IDM_GUID_SYSTEM = os.getenv("IDM_GUID_SYSTEM", "")
IDM_LOGIN = os.getenv("IDM_LOGIN", "")
IDM_CREDENTIAL_SERVICE = os.getenv("IDM_CREDENTIAL_SERVICE", "idm-mcp")

# Default domain code for searches (e.g. "ACME", "MYCORP"). Leave empty if
# you don't want to implicitly filter by domain.
IDM_DEFAULT_DOMAIN = os.getenv("IDM_DEFAULT_DOMAIN", "")

# User attribute code for custom_attribute_2 — differs per IDM tenant.
# Configurable for generic use across organizations.
IDM_CUSTOM_ATTRIBUTE_2_CODE = os.getenv("IDM_CUSTOM_ATTRIBUTE_2_CODE", "AD_CUSTOM_ATTRIBUTE_2")


def resolve_idm_password(login: str, service: str) -> str:
    """Load the IDM secret from the operating system keychain."""
    if not login:
        return ""

    try:
        return keyring.get_password(service, login) or ""
    except keyring.errors.KeyringError as error:
        raise RuntimeError(
            f"Unable to read IDM credentials from the OS keychain service '{service}'."
        ) from error


def store_credentials_cli() -> None:
    """Store the IDM secret in the operating system keychain without echoing it."""
    login = input(f"IDM login [{IDM_LOGIN}]: ").strip() or IDM_LOGIN
    if not login:
        sys.stderr.write("IDM login is required (set IDM_LOGIN or enter it here).\n")
        raise SystemExit(1)

    if not sys.stdin.isatty():
        sys.stderr.write("Credential storage must be run from an interactive terminal.\n")
        raise SystemExit(1)

    password = getpass.getpass("IDM password: ")
    if not password:
        sys.stderr.write("IDM password is required.\n")
        raise SystemExit(1)

    try:
        keyring.set_password(IDM_CREDENTIAL_SERVICE, login, password)
    except keyring.errors.KeyringError as error:
        sys.stderr.write(f"Failed to store IDM credentials: {error}\n")
        raise SystemExit(1) from error

    print(
        f"Stored IDM credentials in the OS keychain "
        f"(service='{IDM_CREDENTIAL_SERVICE}', account='{login}')."
    )
    raise SystemExit(0)


class IdmApiClient:
    """Client for the IDM SOAP API"""

    def __init__(self):
        self.endpoint = IDM_ENDPOINT
        self.guid_system = IDM_GUID_SYSTEM
        self.login = IDM_LOGIN
        self.password = ""
        self.session_guid: Optional[str] = None

    def _make_request(self, body: str, retry_on_auth_error: bool = True) -> ET.Element:
        """Performs a SOAP request"""
        response = requests.post(
            self.endpoint,
            data=body,
            headers={"Content-Type": "application/xml"},  # No charset= to match PowerShell
            timeout=60,  # Increased timeout
            verify=False,  # Disable SSL verification for the IDM API
        )

        # Check the response
        if response.status_code != 200:
            # If it's a 500 and contains a session error, try to re-authenticate
            if response.status_code == 500 and retry_on_auth_error:
                error_text = response.text.lower()
                if 'session' in error_text or 'guid' in error_text or 'prihlaseni' in error_text:
                    sys.stderr.write("Session expired, re-authenticating...\n")
                    self.session_guid = None
                    self.login_to_idm()
                    # Retry the request once
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

        # Check whether the response contains an error
        for elem in root.iter():
            if elem.tag.endswith('errorMessage') or elem.tag.endswith('error'):
                error_msg = elem.text or "Unknown error"
                raise Exception(f"IDM API Error: {error_msg}")

        return root

    def _extract_text(self, root: ET.Element, tag: str) -> Optional[str]:
        """Extracts text from an XML element"""
        # Look for the element regardless of namespace
        for elem in root.iter():
            if elem.tag.endswith(tag):
                return elem.text
        return None

    def _extract_all(self, root: ET.Element, tag: str) -> List[ET.Element]:
        """Extracts all elements with the given tag"""
        result = []
        for elem in root.iter():
            if elem.tag.endswith(tag):
                result.append(elem)
        return result

    def login_to_idm(self) -> str:
        """Logs in to IDM"""
        self.password = resolve_idm_password(self.login, IDM_CREDENTIAL_SERVICE)
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
        """Ensures a valid session"""
        if not self.session_guid:
            self.login_to_idm()
        return self.session_guid

    def get_list_user_group(
        self,
        organization_code: Optional[str] = None,
        domain_code: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Gets the list of groups"""
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

        # Extract groups
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
        """Gets group detail"""
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

        # Extract group detail
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

        # Extract members
        members = []
        users_parent = None
        for elem in root.iter():
            if elem.tag.endswith('users'):
                users_parent = elem
                break

        if users_parent is not None:
            for user_elem in users_parent:
                if user_elem.tag.endswith('user'):
                    member = {
                        "id": self._extract_text(user_elem, "idUser") or self._extract_text(user_elem, "id"),
                        "login": self._extract_text(user_elem, "login"),
                        "domain": self._extract_text(user_elem, "domain"),
                        "firstName": self._extract_text(user_elem, "firstName"),
                        "surname": self._extract_text(user_elem, "surname"),
                        "email": self._extract_text(user_elem, "email"),
                        "status": self._extract_text(user_elem, "status"),
                    }
                    members.append(member)
        else:
            for user_elem in self._extract_all(root, "user"):
                member = {
                    "id": self._extract_text(user_elem, "idUser") or self._extract_text(user_elem, "id"),
                    "login": self._extract_text(user_elem, "login"),
                    "domain": self._extract_text(user_elem, "domain"),
                    "firstName": self._extract_text(user_elem, "firstName"),
                    "surname": self._extract_text(user_elem, "surname"),
                    "email": self._extract_text(user_elem, "email"),
                    "status": self._extract_text(user_elem, "status"),
                }
                members.append(member)

        return {"group": group, "members": members, "memberCount": len(members)}

    def get_child_groups(
        self,
        name_user_group: str,
        domain_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Gets child groups of the given group — parses <childs><child> from the getDetailUserGroup response"""
        session = self.ensure_session()

        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:cz:autocont:idm:interface:external">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:getDetailUserGroup>
                    <ExDetailUserGroupRequest>
                        <guidSystem>{self.guid_system}</guidSystem>
                        <guidSession>{session}</guidSession>
                        <nameUserGroup>{name_user_group}</nameUserGroup>"""

        if domain_code:
            body += f"<domainCode>{domain_code}</domainCode>"

        body += """<includeUserInGroup>false</includeUserInGroup>
                    </ExDetailUserGroupRequest>
                </urn:getDetailUserGroup>
            </soapenv:Body>
        </soapenv:Envelope>"""

        root = self._make_request(body)

        # Child groups are in the <childs><child> elements
        children = []
        for childs_elem in self._extract_all(root, "childs"):
            for child_elem in self._extract_all(childs_elem, "child"):
                children.append({
                    "id": self._extract_text(child_elem, "idRecord"),
                    "code": self._extract_text(child_elem, "code"),
                    "name": self._extract_text(child_elem, "name"),
                })

        return {"parent": name_user_group, "children": children, "childCount": len(children)}

    def get_list_user(
        self,
        organization_code: Optional[str] = None,
        domain_code: Optional[str] = None,
        status: Optional[str] = None,
        user_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Gets the list of users"""
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

        # Extract users
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
        """Gets user detail"""
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
        """Adds a user to a group"""
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
        """Removes a user from a group"""
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
        domain_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Creates a new group in IDM

        Args:
            name: Name of the new group
            user_group_type: Group type (APPLICATION_GROUP, AD_SECURITY, AD_DISTRIBUTION)
            user_group_scope: Group scope (GLOBAL, LOCAL, UNIVERSAL) - typically for AD groups
            description: Group description
            info: Additional info
            email: Group email
            denied_in_permission: Denied in permission flag
            domain_code: Domain code
        """
        session = self.ensure_session()

        body = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:cz:autocont:idm:interface:external">
            <soapenv:Header/>
            <soapenv:Body>
                <urn:createUserGroup>
                    <ExCreateUserGroupRequest>
                        <guidSystem>{self.guid_system}</guidSystem>
                        <guidSession>{session}</guidSession>
                        <name>{name}</name>"""

        if domain_code:
            body += f"<domainCode>{domain_code}</domainCode>"

        body += f"<userGroupType>{user_group_type}</userGroupType>"

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
        """Changes the group name and other attributes

        The function first fetches the group detail to preserve the current
        values, then applies the change only to the specified fields.
        """
        session = self.ensure_session()

        # First fetch the group detail to preserve current values
        current_group = self.get_detail_user_group(
            name_user_group=search_user_group_name,
            domain_code=search_domain_code,
            include_user_in_group=False,
        )

        group_info = current_group['group']

        # Use current values when new ones are not specified
        # Handle None values - if a field is None or empty, don't send it
        description = description if description is not None else (group_info.get('description') or '')
        email = email if email is not None else (group_info.get('email') or '')
        info = info if info is not None else ''  # info is not in the API response, use an empty string
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

        # Only include fields that are not empty
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
        """Saves a user attribute on an entity (e.g. a group)

        Args:
            entity_code: Entity code (e.g. "T_USER_GROUP" for groups)
            id_object: Object ID (e.g. group ID)
            user_attribute_code: Attribute code (e.g. "AD_CUSTOM_ATTRIBUTE_2")
            user_attribute_value: Attribute value (e.g. "resource")
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
        """Removes a parent group from a child group

        Args:
            user_group_name: Child group name
            parent_user_group_name: Name of the parent group to remove
            domain_code: Domain code (optional)
            user_group_id: Child group ID (optional)
            user_group_code: Child group code (optional)
            parent_user_group_id: Parent group ID (optional)
            parent_user_group_code: Parent group code (optional)
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
        """Adds a parent group to a child group (parent record in IDM)

        Args:
            user_group_name: Child group name (the group to which we add a parent)
            parent_user_group_name: Parent group name (the group that becomes the parent)
            domain_code: Domain code (optional)
            user_group_id: Child group ID (optional, alternative to user_group_name)
            user_group_code: Child group code (optional)
            parent_user_group_id: Parent group ID (optional, alternative to parent_user_group_name)
            parent_user_group_code: Parent group code (optional)
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


# Create the global client
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
    Searches groups in IDM by various criteria

    ⚠️ IMPORTANT NOTE:
    - If you're looking for a SPECIFIC group (you know the exact name), use idm_get_group_detail!
    - idm_get_group_detail is 100x faster than search
    - This tool loads ALL groups and then filters — it can be VERY SLOW!
    - ALWAYS specify name_contains for faster searching!

    Args:
        name_contains: Part of the group name to search for (STRONGLY RECOMMENDED!)
        organization_code: Organization code (optional)
        domain_code: Domain code (default: IDM_DEFAULT_DOMAIN env var, other domains: ask user)
        status: Group status - ACTIVE or INACTIVE (optional)
        max_results: Maximum number of returned results (default: 100)

    Returns:
        A dict with the list of groups and their count
    """
    # Load groups from IDM
    result = idm_client.get_list_user_group(organization_code, domain_code, status)

    groups = result['groups']

    # If name_contains is specified, filter locally
    if name_contains:
        name_lower = name_contains.lower()
        groups = [
            g for g in groups
            if name_lower in (g['name'] or '').lower()
        ]

    # Limit the results
    if len(groups) > max_results:
        groups = groups[:max_results]
        return {
            "count": len(groups),
            "groups": groups,
            "warning": f"Only the first {max_results} results out of the total are shown. Narrow the search using name_contains or use idm_get_group_detail for a specific group."
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
    Gets the detail of a specific group including members

    🎯 The FASTEST way to get info about a group!
    Use this tool instead of idm_search_groups when you know the exact group name.

    Args:
        name_user_group: Group name (required unless id_user_group is given)
        domain_code: Domain code (default: IDM_DEFAULT_DOMAIN env var, recommended to always specify)
        id_user_group: Group ID (alternative to name_user_group)
        include_members: Include the list of members (default: True)
        user_status: Filter users by status - ACTIVE or INACTIVE (optional)

    Returns:
        A dict with the group detail and the list of members
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
    Searches users in IDM

    ⚠️ WARNING: Can be slow when loading all users!
    Recommended to specify status or organization_code.

    Args:
        organization_code: Organization code (optional)
        domain_code: Domain code (default: IDM_DEFAULT_DOMAIN env var)
        status: User status - ACTIVE or INACTIVE (recommended!)
        user_type: User type (optional)

    Returns:
        A dict with the list of users
    """
    return idm_client.get_list_user(organization_code, domain_code, status, user_type)


@mcp.tool()
def idm_get_user_detail(
    login: str = None,
    domain: str = IDM_DEFAULT_DOMAIN,
    email: str = None,
) -> Dict[str, Any]:
    """
    Gets the detail of a specific user

    Args:
        login: User login (required unless email is given)
        domain: User domain (default: IDM_DEFAULT_DOMAIN env var, recommended to always specify)
        email: User email (alternative to login)

    Returns:
        A dict with the user detail
    """
    return idm_client.get_detail_user(login=login, email=email, domain=domain)


@mcp.tool()
def idm_add_user_to_group(
    login: str,
    name_user_group: str,
    domain: str = IDM_DEFAULT_DOMAIN,
) -> str:
    """
    Adds a user to a group

    Args:
        login: User login (required)
        name_user_group: Group name (required)
        domain: User domain (optional, recommended)

    Returns:
        Confirmation message
    """
    idm_client.add_user_to_group(login, name_user_group, domain)
    return f"User {login} was added to group {name_user_group}"


@mcp.tool()
def idm_remove_user_from_group(
    login: str,
    name_user_group: str,
    domain: str = IDM_DEFAULT_DOMAIN,
) -> str:
    """
    Removes a user from a group

    Args:
        login: User login (required)
        name_user_group: Group name (required)
        domain: User domain (optional, recommended)

    Returns:
        Confirmation message
    """
    idm_client.remove_user_from_group(login, name_user_group, domain)
    return f"User {login} was removed from group {name_user_group}"


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
    Renames a group in IDM

    ⚠️ IMPORTANT: This operation changes the group name!
    If description, info, email, status or user_group_type are not specified, the current values are preserved.

    Args:
        current_name: Current group name (required)
        new_name: New group name (required)
        domain_code: Domain code (default: IDM_DEFAULT_DOMAIN env var)
        user_group_type: Group type (optional, current value preserved if not specified)
            Possible values:
            - "APPLICATION_GROUP" - Application group (No AD)
            - "AD_SECURITY" - AD Security group
            - "AD_DISTRIBUTION" - AD Distribution group
        user_group_scope: Group scope (optional, current value preserved if not specified)
            Possible values:
            - "GLOBAL" - Global
            - "LOCAL" - Domain Local
            - "UNIVERSAL" - Universal
        description: New description (optional, current value preserved if not specified)
        info: New info (optional, current value preserved if not specified)
        email: New email (optional, current value preserved if not specified)
        status: New status (optional, current value preserved if not specified)

    Returns:
        Confirmation message
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
    result_msg = f"Group '{current_name}' was renamed to '{new_name}'"
    if user_group_type:
        result_msg += f", type: {user_group_type}"
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
    Adds a parent group to a child group (creates a parent record in IDM)

    This function allows you to create a hierarchical relationship between groups.
    The child group "inherits" members from the parent group.

    Example use case:
    - Child: "G_DP_DEVELOPMENT_Specialist" (competence)
    - Parent: "d_special_heads" (resource group)
    → The competence gains access to the resource group

    Args:
        child_group_name: Child group name (the group to which we add a parent)
        parent_group_name: Parent group name (resource group added as a parent record)
        domain_code: Domain code (default: IDM_DEFAULT_DOMAIN env var)

    Returns:
        Confirmation message
    """
    idm_client.add_user_group_parent(
        user_group_name=child_group_name,
        parent_user_group_name=parent_group_name,
        domain_code=domain_code,
    )
    return f"Parent group '{parent_group_name}' was added to group '{child_group_name}' in domain {domain_code}"


@mcp.tool()
def idm_remove_group_parent(
    child_group_name: str,
    parent_group_name: str,
    domain_code: str = IDM_DEFAULT_DOMAIN,
) -> str:
    """
    Removes a parent group from a child group in IDM

    Args:
        child_group_name: Child group name (the group from which we remove a parent)
        parent_group_name: Name of the parent group to remove
        domain_code: Domain code (default: IDM_DEFAULT_DOMAIN env var)

    Returns:
        Confirmation message
    """
    idm_client.remove_user_group_parent(
        user_group_name=child_group_name,
        parent_user_group_name=parent_group_name,
        domain_code=domain_code,
    )
    return f"Parent group '{parent_group_name}' was removed from group '{child_group_name}' in domain {domain_code}"


@mcp.tool()
def idm_set_group_attribute(
    group_name: str,
    attribute_code: str,
    attribute_value: str,
    domain_code: str = IDM_DEFAULT_DOMAIN,
) -> str:
    """
    Sets a user attribute on a group in IDM

    This function allows you to set custom attributes such as customAttribute2.

    Args:
        group_name: Group name (required)
        attribute_code: Attribute code (required)
            Common values:
            - "AD_CUSTOM_ATTRIBUTE_2" - customAttribute2 (e.g. "resource", "competence")
        attribute_value: Attribute value (required)
            For AD_CUSTOM_ATTRIBUTE_2:
            - "resource" - resource group
            - "competence" - competence group
        domain_code: Domain code (default: IDM_DEFAULT_DOMAIN env var)

    Returns:
        Confirmation message
    """
    # First fetch the group ID
    group_detail = idm_client.get_detail_user_group(
        name_user_group=group_name,
        domain_code=domain_code,
        include_user_in_group=False,
    )

    group_id = group_detail['group'].get('id')
    if not group_id:
        raise Exception(f"Group '{group_name}' was not found or has no ID")

    # Set the attribute
    idm_client.save_user_attribute_to_entity(
        entity_code="T_USER_GROUP",
        id_object=group_id,
        user_attribute_code=attribute_code,
        user_attribute_value=attribute_value,
    )

    return f"Attribute '{attribute_code}' = '{attribute_value}' was set for group '{group_name}'"


@mcp.tool()
def idm_create_group(
    name: str,
    group_type: str,
    group_scope: str,
    custom_attribute_2: str,
    description: str = None,
    info: str = None,
    email: str = None,
    denied_in_permission: str = None,
    domain_code: str = IDM_DEFAULT_DOMAIN,
) -> str:
    """
    Creates a new group in IDM

    ⚠️ IMPORTANT: This operation creates a new group in IDM!

    REQUIRED parameters: group_type, group_scope, custom_attribute_2
    The group is not created if any of these parameters is missing.
    After creation, the attribute defined by the IDM_CUSTOM_ATTRIBUTE_2_CODE
    environment variable is automatically set.

    Args:
        name: Name of the new group (required)
        group_type: Group type (required)
            Possible values:
            - "NO_AD" or "APPLICATION_GROUP" - Application group without AD
            - "AD_SECURITY" - AD Security group
            - "AD_DISTRIBUTION" - AD Distribution group
        group_scope: Group scope (required)
            Possible values:
            - "GLOBAL" - Global
            - "LOCAL" or "DOMAIN_LOCAL" - Domain Local
            - "UNIVERSAL" - Universal
        custom_attribute_2: Value for the IDM_CUSTOM_ATTRIBUTE_2_CODE attribute (required)
            Common values: "resource", "competence", "application"
        description: Group description (optional)
        info: Additional info (optional)
        email: Group email (optional)
        denied_in_permission: Denied in permission flag (optional)
        domain_code: Domain code (default: IDM_DEFAULT_DOMAIN env var)

    Returns:
        Confirmation message with the ID of the newly created group and the attribute that was set
    """
    missing = []
    if not group_type:
        missing.append("group_type")
    if not group_scope:
        missing.append("group_scope")
    if not custom_attribute_2:
        missing.append(f"custom_attribute_2 ({IDM_CUSTOM_ATTRIBUTE_2_CODE})")
    if missing:
        raise ValueError(f"Group was not created. Missing required parameters: {', '.join(missing)}")

    # Map user-friendly names to API values (same as in idm_change_group)
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
    api_group_scope = scope_mapping.get(group_scope.upper(), group_scope)

    result = idm_client.create_user_group(
        name=name,
        user_group_type=api_group_type,
        user_group_scope=api_group_scope,
        description=description,
        info=info,
        email=email,
        denied_in_permission=denied_in_permission,
        domain_code=domain_code or None,
    )

    msg = f"Group '{name}' was created (type: {api_group_type}, scope: {api_group_scope})"

    # If createUserGroup did not return an ID, look it up by name
    group_id = result.get("id")
    if not group_id:
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

    # Set custom_attribute_2
    if group_id:
        idm_client.save_user_attribute_to_entity(
            entity_code="T_USER_GROUP",
            id_object=group_id,
            user_attribute_code=IDM_CUSTOM_ATTRIBUTE_2_CODE,
            user_attribute_value=custom_attribute_2,
        )
        msg += f", {IDM_CUSTOM_ATTRIBUTE_2_CODE}: {custom_attribute_2}"
    else:
        raise Exception(f"Group '{name}' was created, but its ID could not be found — attribute {IDM_CUSTOM_ATTRIBUTE_2_CODE} was not set")

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
    Changes group properties in IDM (name, type, scope, custom attributes)

    This is the main tool for updating groups. It allows changing multiple properties at once.

    Args:
        group_name: Current group name (required)
        new_name: New group name (optional, name is unchanged if not given)
        group_type: Group type (optional)
            Possible values:
            - "NO_AD" or "APPLICATION_GROUP" - Application group without AD
            - "AD_SECURITY" - AD Security group
            - "AD_DISTRIBUTION" - AD Distribution group
        group_scope: Group scope (optional)
            Possible values:
            - "GLOBAL" - Global
            - "LOCAL" - Domain Local
            - "UNIVERSAL" - Universal
        custom_attribute_2: Value for customAttribute2 (optional)
            Common values: "resource", "competence"
        description: New description (optional)
        info: New info (optional)
        email: New email (optional)
        status: New status - "ACTIVE" or "INACTIVE" (optional)
        domain_code: Domain code (default: IDM_DEFAULT_DOMAIN env var)

    Returns:
        Confirmation message with all changes applied
    """
    changes = []

    # Map user-friendly names to API values
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

    # Convert user-friendly values to API values
    api_group_type = None
    if group_type:
        api_group_type = type_mapping.get(group_type.upper(), group_type)
        changes.append(f"type: {api_group_type}")

    api_group_scope = None
    if group_scope:
        api_group_scope = scope_mapping.get(group_scope.upper(), group_scope)
        changes.append(f"scope: {api_group_scope}")

    # If the name or other basic properties change, call changeUserGroup
    effective_new_name = new_name if new_name else group_name

    if new_name:
        changes.append(f"name: {group_name} → {new_name}")

    if description:
        changes.append(f"description: {description}")

    # Always call changeUserGroup (even if only to preserve consistency)
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

    # If custom_attribute_2 is changing, call saveUserAttributeToEntity
    if custom_attribute_2:
        # Fetch the group ID (use the new name if it was changed)
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
            changes.append(f"⚠️ customAttribute2 was not set - group has no ID")

    if not changes:
        return f"Group '{group_name}' - no changes were specified"

    return f"Group '{group_name}' was updated: {', '.join(changes)}"


@mcp.tool()
def idm_get_child_groups(
    name_user_group: str,
    domain_code: str = IDM_DEFAULT_DOMAIN,
) -> Dict[str, Any]:
    """
    Gets the child groups (subgroups) of a given group

    Use this tool when you need to find out which groups are subordinate
    to a given group (i.e. have this group as their parent).

    Args:
        name_user_group: Parent group name (required)
        domain_code: Domain code (default: IDM_DEFAULT_DOMAIN env var)

    Returns:
        A dict with the parent group name, the list of child groups and their count
    """
    return idm_client.get_child_groups(
        name_user_group=name_user_group,
        domain_code=domain_code or None,
    )


@mcp.tool()
def idm_login() -> str:
    """
    Logs in to IDM and refreshes the session

    Use this when:
    - The session expired and other tools report "Session does not exist or has expired"
    - You want to verify that login works

    Returns:
        Confirmation of successful login with the session GUID
    """
    idm_client.session_guid = None
    guid_session = idm_client.login_to_idm()
    return f"Login successful. Session GUID: {guid_session}"


# Start the server
if __name__ == "__main__":
    if "--store-credentials" in sys.argv:
        store_credentials_cli()

    # Check credentials
    idm_client.password = resolve_idm_password(IDM_LOGIN, IDM_CREDENTIAL_SERVICE)
    if not all([IDM_GUID_SYSTEM, IDM_LOGIN, idm_client.password]):
        sys.stderr.write("Error: IDM credentials not configured!\n")
        sys.stderr.write(
            "Set IDM_GUID_SYSTEM and IDM_LOGIN, then run "
            "'python idm_mcp.py --store-credentials' to save the secret "
            "in the OS keychain.\n"
        )
        exit(1)

    # Start the server (login happens automatically on the first call)
    mcp.run()
