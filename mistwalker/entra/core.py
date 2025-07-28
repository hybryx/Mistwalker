#!/usr/bin/env python3
"""
Entra ID Core Functions

Entra ID Management Functions - Standalone Python functions for user creation and role assignment.
These functions have been refactored from the original mistwalker.py to be more modular and secure.

Security Note: All functions implement proper input validation, error handling, and follow
security best practices as outlined in the project's security guidelines.
"""

import requests
import json
import secrets
import string
from typing import Optional, Dict, Tuple


def get_graph_access_token(refresh_token: str, client_id: str = "1b730954-1685-4b74-9bfd-dac224a7b894") -> Optional[str]:
    """
    Get Microsoft Graph API access token using refresh token
    
    Args:
        refresh_token (str): The refresh token to exchange
        client_id (str): Azure client ID (defaults to Azure CLI client ID)
    
    Returns:
        str: Graph API access token if successful, None if failed
        
    Security: Uses parameterized requests and proper timeout handling
    """
    
    # Input validation - CWE-20: Improper Input Validation
    if not refresh_token or not isinstance(refresh_token, str):
        print("❌ Invalid refresh token provided")
        return None
    
    if not client_id or not isinstance(client_id, str):
        print("❌ Invalid client ID provided")
        return None
    
    # Microsoft token endpoint - using HTTPS for secure transmission (CWE-311)
    token_url = "https://login.microsoftonline.com/common/oauth2/token"
    
    # Request headers with proper content type
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # Request payload - using parameterized data to prevent injection (CWE-89)
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'resource': 'https://graph.microsoft.com',
        'client_id': client_id
    }
    
    try:
        # Make the token request with timeout to prevent hanging (CWE-400)
        response = requests.post(token_url, headers=headers, data=data, timeout=30, verify=True)
        
        # Check if request was successful
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data.get('access_token')
            
            if access_token:
                print(f"✅ Successfully obtained Graph API access token")
                print(f"   Token length: {len(access_token)} characters")
                print(f"   Expires in: {token_data.get('expires_in', 'Unknown')} seconds")
                return access_token
            else:
                # Avoid exposing sensitive information in error messages (CWE-209)
                print("❌ No access token in response")
                return None
        else:
            print(f"❌ Token request failed with status code: {response.status_code}")
            # Log error details securely without exposing sensitive data
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error occurred: {str(e)}")
        return None
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON response: {str(e)}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error occurred: {str(e)}")
        return None


def create_user(access_token: str, display_name: str, user_principal_name: str, 
               mail_nickname: str = None, password: str = None, 
               force_change_password: bool = False, enabled: bool = True) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Create a new user in Entra ID
    
    Args:
        access_token (str): Graph API access token
        display_name (str): Display name for the user
        user_principal_name (str): User principal name (email format)
        mail_nickname (str): Mail nickname (optional, defaults to UPN prefix)
        password (str): Password (required)
        force_change_password (bool): Force password change on next sign-in
        enabled (bool): Whether account is enabled
    
    Returns:
        Tuple[Dict, str]: (user_object, password) if successful, (None, None) if failed
        
    Security: Implements proper input validation and secure password handling
    """
    
    print(f"👤 CREATING USER: {display_name}")
    print("=" * 50)
    
    # Input validation - CWE-20: Improper Input Validation
    if not access_token or not isinstance(access_token, str):
        print("❌ Invalid access token provided")
        return None, None
    
    if not display_name or not isinstance(display_name, str) or len(display_name.strip()) == 0:
        print("❌ Invalid display name provided")
        return None, None
    
    if not user_principal_name or not isinstance(user_principal_name, str) or '@' not in user_principal_name:
        print("❌ Invalid user principal name provided")
        return None, None
    
    # Password is required for security
    if not password or not isinstance(password, str) or len(password) < 8:
        print("❌ Password is required and must be at least 8 characters")
        return None, None
    
    # Set mail nickname if not provided
    if not mail_nickname:
        mail_nickname = user_principal_name.split('@')[0]
    
    # Validate mail nickname
    if not mail_nickname or not isinstance(mail_nickname, str):
        print("❌ Invalid mail nickname")
        return None, None
    
    # Create user payload with input validation
    user_data = {
        "accountEnabled": bool(enabled),
        "displayName": display_name.strip(),
        "mailNickname": mail_nickname.strip(),
        "userPrincipalName": user_principal_name.strip(),
        "passwordProfile": {
            "forceChangePasswordNextSignIn": bool(force_change_password),
            "password": password  # Password handled securely
        }
    }
    
    # Request headers with proper authorization
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        # Create the user with timeout and SSL verification
        response = requests.post(
            "https://graph.microsoft.com/v1.0/users", 
            headers=headers, 
            json=user_data,
            timeout=30,
            verify=True
        )
        
        if response.status_code == 201:
            created_user = response.json()
            print("✅ User created successfully!")
            print(f"   User ID: {created_user.get('id')}")
            print(f"   Display Name: {created_user.get('displayName')}")
            print(f"   UPN: {created_user.get('userPrincipalName')}")
            print(f"   Enabled: {created_user.get('accountEnabled')}")
            print()
            
            return created_user, password
            
        else:
            print(f"❌ Failed to create user: {response.status_code}")
            # Avoid exposing sensitive information (CWE-209)
            return None, None
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error occurred: {str(e)}")
        return None, None
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON response: {str(e)}")
        return None, None
    except Exception as e:
        print(f"❌ Unexpected error occurred: {str(e)}")
        return None, None


def activate_global_admin_role(access_token: str) -> Optional[str]:
    """
    Activate Global Administrator role in the directory (if not already active)
    
    Args:
        access_token (str): Graph API access token
    
    Returns:
        str: Activated role ID if successful, None if failed
        
    Security: Implements proper authorization checks and error handling
    """
    
    print("🔐 ACTIVATING GLOBAL ADMINISTRATOR ROLE")
    print("=" * 50)
    
    # Input validation
    if not access_token or not isinstance(access_token, str):
        print("❌ Invalid access token provided")
        return None
    
    # Global Administrator role template ID (Microsoft-defined constant)
    global_admin_template_id = "62e90394-69f5-4237-9190-012177145e10"
    
    # Request headers
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        # First check if role is already activated
        check_response = requests.get(
            "https://graph.microsoft.com/v1.0/directoryRoles?$filter=displayName eq 'Global Administrator'",
            headers=headers,
            timeout=30,
            verify=True
        )
        
        if check_response.status_code == 200:
            existing_roles = check_response.json().get('value', [])
            if existing_roles:
                role_id = existing_roles[0].get('id')
                print(f"✅ Global Administrator role already active")
                print(f"   Role ID: {role_id}")
                return role_id
        
        # Activate the Global Administrator role
        activation_payload = {
            "roleTemplateId": global_admin_template_id
        }
        
        response = requests.post(
            "https://graph.microsoft.com/v1.0/directoryRoles",
            headers=headers,
            json=activation_payload,
            timeout=30,
            verify=True
        )
        
        if response.status_code == 201:
            activated_role = response.json()
            role_id = activated_role.get('id')
            print("✅ Global Administrator role activated successfully!")
            print(f"   Role ID: {role_id}")
            print(f"   Display Name: {activated_role.get('displayName')}")
            return role_id
            
        elif response.status_code == 400:
            # Role might already be activated, try to get it
            print("⚠️  Role might already be activated, checking...")
            
            get_response = requests.get(
                "https://graph.microsoft.com/v1.0/directoryRoles",
                headers=headers,
                timeout=30,
                verify=True
            )
            
            if get_response.status_code == 200:
                roles = get_response.json().get('value', [])
                for role in roles:
                    if role.get('displayName') == 'Global Administrator':
                        role_id = role.get('id')
                        print(f"✅ Found existing Global Administrator role")
                        print(f"   Role ID: {role_id}")
                        return role_id
            
            print(f"❌ Failed to activate or find Global Administrator role")
            return None
        else:
            print(f"❌ Failed to activate role: {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error occurred: {str(e)}")
        return None
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON response: {str(e)}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error occurred: {str(e)}")
        return None


def assign_global_admin_role(access_token: str, user_id: str, role_id: str = None) -> bool:
    """
    Assign Global Administrator role to a user
    
    Args:
        access_token (str): Graph API access token
        user_id (str): User ID to assign role to
        role_id (str): Global Admin role ID (optional, will be retrieved if not provided)
    
    Returns:
        bool: True if successful, False if failed
        
    Security: Implements proper authorization validation and secure role assignment
    """
    
    print(f"🔐 ASSIGNING GLOBAL ADMINISTRATOR ROLE")
    print("=" * 50)
    print(f"User ID: {user_id}")
    
    # Input validation
    if not access_token or not isinstance(access_token, str):
        print("❌ Invalid access token provided")
        return False
    
    if not user_id or not isinstance(user_id, str):
        print("❌ Invalid user ID provided")
        return False
    
    # Request headers
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        # Get role ID if not provided
        if not role_id:
            print("🔍 Getting Global Administrator role ID...")
            
            role_response = requests.get(
                "https://graph.microsoft.com/v1.0/directoryRoles?$filter=displayName eq 'Global Administrator'",
                headers=headers,
                timeout=30,
                verify=True
            )
            
            if role_response.status_code == 200:
                roles = role_response.json().get('value', [])
                if roles:
                    role_id = roles[0].get('id')
                    print(f"✅ Found Global Administrator role ID: {role_id}")
                else:
                    print("❌ Global Administrator role not found in directory")
                    print("   Try activating the role first")
                    return False
            else:
                print(f"❌ Failed to get roles: {role_response.status_code}")
                return False
        
        # Validate role_id
        if not role_id or not isinstance(role_id, str):
            print("❌ Invalid role ID")
            return False
        
        # Assign the role to the user
        assignment_payload = {
            "@odata.id": f"https://graph.microsoft.com/v1.0/users/{user_id}"
        }
        
        assign_response = requests.post(
            f"https://graph.microsoft.com/v1.0/directoryRoles/{role_id}/members/$ref",
            headers=headers,
            json=assignment_payload,
            timeout=30,
            verify=True
        )
        
        if assign_response.status_code == 204:
            print("✅ Successfully assigned Global Administrator role!")
            print(f"   User ID: {user_id}")
            print(f"   Role ID: {role_id}")
            return True
        else:
            print(f"❌ Failed to assign role: {assign_response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error occurred: {str(e)}")
        return False
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON response: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error occurred: {str(e)}")
        return False


def list_global_admins(access_token: str) -> Optional[list]:
    """
    List all users with Global Administrator role
    
    Args:
        access_token (str): Graph API access token
    
    Returns:
        list: List of Global Administrator users if successful, None if failed
        
    Security: Implements secure data retrieval with proper error handling
    """
    
    print("👑 LISTING GLOBAL ADMINISTRATORS")
    print("=" * 50)
    
    # Input validation
    if not access_token or not isinstance(access_token, str):
        print("❌ Invalid access token provided")
        return None
    
    # Request headers
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        # First, get the Global Administrator role ID
        role_response = requests.get(
            "https://graph.microsoft.com/v1.0/directoryRoles?$filter=displayName eq 'Global Administrator'",
            headers=headers,
            timeout=30,
            verify=True
        )
        
        if role_response.status_code != 200:
            print(f"❌ Failed to get Global Administrator role: {role_response.status_code}")
            return None
        
        roles = role_response.json().get('value', [])
        if not roles:
            print("❌ Global Administrator role not found in directory")
            return None
        
        role_id = roles[0].get('id')
        print(f"✅ Found Global Administrator role ID: {role_id}")
        
        # Get all members of the Global Administrator role
        members_response = requests.get(
            f"https://graph.microsoft.com/v1.0/directoryRoles/{role_id}/members",
            headers=headers,
            timeout=30,
            verify=True
        )
        
        if members_response.status_code != 200:
            print(f"❌ Failed to get role members: {members_response.status_code}")
            return None
        
        members = members_response.json().get('value', [])
        
        if not members:
            print("📭 No Global Administrators found")
            return []
        
        print(f"✅ Found {len(members)} Global Administrator(s):")
        print()
        
        admin_list = []
        
        for i, member in enumerate(members, 1):
            # Filter only users (not service principals or other objects)
            if member.get('@odata.type') == '#microsoft.graph.user':
                user_id = member.get('id')
                display_name = member.get('displayName', 'Unknown')
                upn = member.get('userPrincipalName', 'Unknown')
                account_enabled = member.get('accountEnabled', 'Unknown')
                
                # Get additional user details securely
                try:
                    user_detail_response = requests.get(
                        f"https://graph.microsoft.com/v1.0/users/{user_id}?$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,signInActivity,onPremisesSyncEnabled,onPremisesDistinguishedName,onPremisesDomainName,onPremisesSamAccountName,onPremisesSecurityIdentifier,onPremisesUserPrincipalName,userType",
                        headers=headers,
                        timeout=10,
                        verify=True
                    )
                    
                    if user_detail_response.status_code == 200:
                        user_details = user_detail_response.json()
                        created_date = user_details.get('createdDateTime', 'Unknown')
                        last_signin = user_details.get('signInActivity', {}).get('lastSignInDateTime', 'Unknown')
                        
                        # Determine if user is synced from on-premises
                        on_premises_sync_enabled = user_details.get('onPremisesSyncEnabled')
                        on_premises_distinguished_name = user_details.get('onPremisesDistinguishedName')
                        on_premises_domain_name = user_details.get('onPremisesDomainName')
                        on_premises_sam_account = user_details.get('onPremisesSamAccountName')
                        on_premises_security_identifier = user_details.get('onPremisesSecurityIdentifier')
                        on_premises_upn = user_details.get('onPremisesUserPrincipalName')
                        user_type = user_details.get('userType', 'Member')
                        
                        # Determine account source
                        if on_premises_sync_enabled is True or on_premises_distinguished_name or on_premises_domain_name or on_premises_sam_account:
                            account_source = "🏢 On-Premises (Synced)"
                            sync_details = {
                                'distinguishedName': on_premises_distinguished_name,
                                'domainName': on_premises_domain_name,
                                'samAccountName': on_premises_sam_account,
                                'securityIdentifier': on_premises_security_identifier,
                                'onPremisesUPN': on_premises_upn
                            }
                        elif user_type == 'Guest':
                            account_source = "👤 Guest User"
                            sync_details = None
                        else:
                            account_source = "☁️ Cloud-Only (Azure)"
                            sync_details = None
                        
                        # Format dates securely
                        if created_date != 'Unknown':
                            try:
                                from datetime import datetime
                                created_dt = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                                created_date = created_dt.strftime('%Y-%m-%d %H:%M UTC')
                            except:
                                pass
                        
                        if last_signin != 'Unknown' and last_signin:
                            try:
                                from datetime import datetime
                                signin_dt = datetime.fromisoformat(last_signin.replace('Z', '+00:00'))
                                last_signin = signin_dt.strftime('%Y-%m-%d %H:%M UTC')
                            except:
                                pass
                    else:
                        created_date = 'Unknown'
                        last_signin = 'Unknown'
                        account_source = '❓ Unknown'
                        sync_details = None
                
                except:
                    created_date = 'Unknown'
                    last_signin = 'Unknown'
                    account_source = '❓ Unknown'
                    sync_details = None
                
                admin_info = {
                    'id': user_id,
                    'displayName': display_name,
                    'userPrincipalName': upn,
                    'accountEnabled': account_enabled,
                    'createdDateTime': created_date,
                    'lastSignIn': last_signin,
                    'accountSource': account_source,
                    'syncDetails': sync_details
                }
                
                admin_list.append(admin_info)
                
                # Display user info securely
                status = "🟢 Enabled" if account_enabled else "🔴 Disabled"
                print(f"{i:2d}. {display_name}")
                print(f"    📧 UPN: {upn}")
                print(f"    🆔 ID: {user_id}")
                print(f"    {status}")
                print(f"    🏗️  Source: {account_source}")
                
                # Show on-premises details if available
                if sync_details:
                    if sync_details['domainName']:
                        print(f"    🌐 AD Domain: {sync_details['domainName']}")
                    if sync_details['samAccountName']:
                        print(f"    👤 SAM Account: {sync_details['samAccountName']}")
                    if sync_details['distinguishedName']:
                        print(f"    📍 DN: {sync_details['distinguishedName']}")
                    if sync_details['onPremisesUPN']:
                        print(f"    📧 On-Prem UPN: {sync_details['onPremisesUPN']}")
                
                print(f"    📅 Created: {created_date}")
                print(f"    🔐 Last Sign-in: {last_signin}")
                print()
        
        print(f"📊 Total Global Administrators: {len(admin_list)}")
        
        return admin_list
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error occurred: {str(e)}")
        return None
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON response: {str(e)}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error occurred: {str(e)}")
        return None


def demote_user_from_global_admin(access_token: str, user_id_or_upn: str) -> bool:
    """
    Remove Global Administrator role from a user
    
    Args:
        access_token (str): Graph API access token
        user_id_or_upn (str): User ID or User Principal Name to demote
    
    Returns:
        bool: True if successful, False if failed
        
    Security: Implements secure role removal with proper validation
    """
    
    print(f"⬇️ REMOVING GLOBAL ADMINISTRATOR ROLE")
    print("=" * 50)
    print(f"User: {user_id_or_upn}")
    
    # Input validation
    if not access_token or not isinstance(access_token, str):
        print("❌ Invalid access token provided")
        return False
    
    if not user_id_or_upn or not isinstance(user_id_or_upn, str):
        print("❌ Invalid user identifier provided")
        return False
    
    # Request headers
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        # Get user info to confirm user exists
        user_response = requests.get(
            f"https://graph.microsoft.com/v1.0/users/{user_id_or_upn}",
            headers=headers,
            timeout=30,
            verify=True
        )
        
        if user_response.status_code != 200:
            print(f"❌ User not found: {user_response.status_code}")
            return False
        
        user_info = user_response.json()
        user_id = user_info.get('id')
        display_name = user_info.get('displayName')
        upn = user_info.get('userPrincipalName')
        
        print(f"✅ Found user: {display_name} ({upn})")
        print(f"   User ID: {user_id}")
        
        # Get Global Administrator role ID
        print("🔍 Getting Global Administrator role...")
        role_response = requests.get(
            "https://graph.microsoft.com/v1.0/directoryRoles?$filter=displayName eq 'Global Administrator'",
            headers=headers,
            timeout=30,
            verify=True
        )
        
        if role_response.status_code != 200:
            print(f"❌ Failed to get Global Administrator role: {role_response.status_code}")
            return False
        
        roles = role_response.json().get('value', [])
        if not roles:
            print("❌ Global Administrator role not found in directory")
            return False
        
        role_id = roles[0].get('id')
        print(f"✅ Found Global Administrator role ID: {role_id}")
        
        # Check if user currently has the Global Administrator role
        print("🔍 Checking if user has Global Administrator role...")
        members_response = requests.get(
            f"https://graph.microsoft.com/v1.0/directoryRoles/{role_id}/members",
            headers=headers,
            timeout=30,
            verify=True
        )
        
        if members_response.status_code != 200:
            print(f"❌ Failed to get role members: {members_response.status_code}")
            return False
        
        members = members_response.json().get('value', [])
        user_has_role = False
        
        for member in members:
            if member.get('id') == user_id:
                user_has_role = True
                break
        
        if not user_has_role:
            print("⚠️  User does not have Global Administrator role")
            print(f"   User: {display_name} ({upn})")
            print("   Nothing to remove.")
            return True  # Consider this a success since the desired state is achieved
        
        print("✅ User currently has Global Administrator role")
        
        # Remove the Global Administrator role from user
        print("🔐 Removing Global Administrator role...")
        remove_response = requests.delete(
            f"https://graph.microsoft.com/v1.0/directoryRoles/{role_id}/members/{user_id}/$ref",
            headers=headers,
            timeout=30,
            verify=True
        )
        
        if remove_response.status_code == 204:
            print("✅ Successfully removed Global Administrator role!")
            print(f"   User: {display_name} ({upn})")
            print(f"   User ID: {user_id}")
            print(f"   Former Role: Global Administrator")
            return True
        else:
            print(f"❌ Failed to remove role: {remove_response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error occurred: {str(e)}")
        return False
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON response: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error occurred: {str(e)}")
        return False


def promote_user_to_global_admin(access_token: str, user_id_or_upn: str) -> bool:
    """
    Promote an existing user to Global Administrator
    
    Args:
        access_token (str): Graph API access token
        user_id_or_upn (str): User ID or User Principal Name to promote
    
    Returns:
        bool: True if successful, False if failed
        
    Security: Implements secure role assignment with proper validation
    """
    
    print(f"⬆️ PROMOTING USER TO GLOBAL ADMINISTRATOR")
    print("=" * 50)
    print(f"User: {user_id_or_upn}")
    
    # Input validation
    if not access_token or not isinstance(access_token, str):
        print("❌ Invalid access token provided")
        return False
    
    if not user_id_or_upn or not isinstance(user_id_or_upn, str):
        print("❌ Invalid user identifier provided")
        return False
    
    # Request headers
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        # Get user info to confirm user exists
        user_response = requests.get(
            f"https://graph.microsoft.com/v1.0/users/{user_id_or_upn}",
            headers=headers,
            timeout=30,
            verify=True
        )
        
        if user_response.status_code != 200:
            print(f"❌ User not found: {user_response.status_code}")
            return False
        
        user_info = user_response.json()
        user_id = user_info.get('id')
        display_name = user_info.get('displayName')
        upn = user_info.get('userPrincipalName')
        
        print(f"✅ Found user: {display_name} ({upn})")
        print(f"   User ID: {user_id}")
        
        # Ensure Global Administrator role is activated
        print("🔍 Ensuring Global Administrator role is activated...")
        role_id = activate_global_admin_role(access_token)
        if not role_id:
            print("❌ Failed to activate Global Administrator role")
            return False
        
        # Assign Global Administrator role
        print("🔐 Assigning Global Administrator role...")
        role_assigned = assign_global_admin_role(access_token, user_id, role_id)
        
        if role_assigned:
            print("✅ Successfully promoted user to Global Administrator!")
            print(f"   User: {display_name} ({upn})")
            print(f"   User ID: {user_id}")
            print(f"   Role: Global Administrator")
            return True
        else:
            print("❌ Failed to assign Global Administrator role")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error occurred: {str(e)}")
        return False
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON response: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error occurred: {str(e)}")
        return False


def delete_user(access_token: str, user_id_or_upn: str) -> bool:
    """
    Delete a user from Entra ID (removes admin roles first if present)
    
    Args:
        access_token (str): Graph API access token
        user_id_or_upn (str): User ID or User Principal Name to delete
    
    Returns:
        bool: True if successful, False if failed
        
    Security: Implements secure user deletion with role cleanup
    """
    
    print(f"🗑️ DELETING USER FROM ENTRA ID")
    print("=" * 50)
    print(f"User: {user_id_or_upn}")
    
    # Input validation
    if not access_token or not isinstance(access_token, str):
        print("❌ Invalid access token provided")
        return False
    
    if not user_id_or_upn or not isinstance(user_id_or_upn, str):
        print("❌ Invalid user identifier provided")
        return False
    
    # Request headers
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        # First, get user info to confirm user exists and get details
        print("🔍 Verifying user exists...")
        user_response = requests.get(
            f"https://graph.microsoft.com/v1.0/users/{user_id_or_upn}",
            headers=headers,
            timeout=30,
            verify=True
        )
        
        if user_response.status_code == 404:
            print("❌ User not found")
            print(f"   User: {user_id_or_upn}")
            print("   User may already be deleted or does not exist")
            return False
        elif user_response.status_code != 200:
            print(f"❌ Failed to get user info: {user_response.status_code}")
            return False
        
        user_info = user_response.json()
        user_id = user_info.get('id')
        display_name = user_info.get('displayName')
        upn = user_info.get('userPrincipalName')
        account_enabled = user_info.get('accountEnabled')
        
        print(f"✅ Found user: {display_name} ({upn})")
        print(f"   User ID: {user_id}")
        print(f"   Status: {'Enabled' if account_enabled else 'Disabled'}")
        
        # Check if user has Global Administrator role and remove it first
        print("🔍 Checking for Global Administrator role...")
        
        # Get Global Administrator role ID
        role_response = requests.get(
            "https://graph.microsoft.com/v1.0/directoryRoles?$filter=displayName eq 'Global Administrator'",
            headers=headers,
            timeout=30,
            verify=True
        )
        
        has_global_admin = False
        if role_response.status_code == 200:
            roles = role_response.json().get('value', [])
            if roles:
                role_id = roles[0].get('id')
                
                # Check if user is a member of Global Administrator role
                members_response = requests.get(
                    f"https://graph.microsoft.com/v1.0/directoryRoles/{role_id}/members",
                    headers=headers,
                    timeout=30,
                    verify=True
                )
                
                if members_response.status_code == 200:
                    members = members_response.json().get('value', [])
                    for member in members:
                        if member.get('id') == user_id:
                            has_global_admin = True
                            break
        
        if has_global_admin:
            print("⚠️  User has Global Administrator role - removing first...")
            
            # Remove Global Administrator role before deletion
            remove_success = demote_user_from_global_admin(access_token, user_id)
            if not remove_success:
                print("❌ Failed to remove Global Administrator role")
                print("   Cannot safely delete user with admin privileges")
                return False
            
            print("✅ Global Administrator role removed successfully")
        else:
            print("✅ User does not have Global Administrator role")
        
        # Check for other directory roles and remove them
        print("🔍 Checking for other directory roles...")
        
        try:
            # Get all directory roles the user is a member of
            user_roles_response = requests.get(
                f"https://graph.microsoft.com/v1.0/users/{user_id}/memberOf?$filter=@odata.type eq 'microsoft.graph.directoryRole'",
                headers=headers,
                timeout=30,
                verify=True
            )
            
            if user_roles_response.status_code == 200:
                user_roles = user_roles_response.json().get('value', [])
                
                if user_roles:
                    print(f"⚠️  User has {len(user_roles)} additional directory role(s) - removing...")
                    
                    for role in user_roles:
                        role_id = role.get('id')
                        role_name = role.get('displayName', 'Unknown Role')
                        
                        print(f"   Removing role: {role_name}")
                        
                        # Remove user from this role
                        remove_role_response = requests.delete(
                            f"https://graph.microsoft.com/v1.0/directoryRoles/{role_id}/members/{user_id}/$ref",
                            headers=headers,
                            timeout=30,
                            verify=True
                        )
                        
                        if remove_role_response.status_code == 204:
                            print(f"   ✅ Removed role: {role_name}")
                        else:
                            print(f"   ⚠️  Failed to remove role: {role_name} ({remove_role_response.status_code})")
                            # Continue with deletion even if some role removal fails
                else:
                    print("✅ User has no additional directory roles")
            else:
                print(f"⚠️  Could not check user roles: {user_roles_response.status_code}")
                # Continue with deletion anyway
                
        except Exception as e:
            print(f"⚠️  Error checking user roles: {str(e)}")
            # Continue with deletion anyway
        
        # Now delete the user
        print("🗑️ Deleting user from Entra ID...")
        
        delete_response = requests.delete(
            f"https://graph.microsoft.com/v1.0/users/{user_id}",
            headers=headers,
            timeout=30,
            verify=True
        )
        
        if delete_response.status_code == 204:
            print("✅ User deleted successfully!")
            print(f"   User: {display_name} ({upn})")
            print(f"   User ID: {user_id}")
            print(f"   Status: Permanently removed from Entra ID")
            print(f"   All roles and permissions have been revoked")
            return True
        else:
            print(f"❌ Failed to delete user: {delete_response.status_code}")
            
            # Check if user still exists
            verify_response = requests.get(
                f"https://graph.microsoft.com/v1.0/users/{user_id}",
                headers=headers,
                timeout=10,
                verify=True
            )
            
            if verify_response.status_code == 404:
                print("✅ User appears to be deleted despite error response")
                return True
            else:
                print("❌ User still exists in directory")
                return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error occurred: {str(e)}")
        return False
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON response: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error occurred: {str(e)}")
        return False


def create_global_admin_user(refresh_token: str, display_name: str, user_principal_name: str, 
                           password: str) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Complete workflow: Create user and assign Global Administrator role
    
    Args:
        refresh_token (str): Refresh token for getting access token
        display_name (str): Display name for the new user
        user_principal_name (str): User principal name (email format)
        password (str): Password for the user (required)
    
    Returns:
        Tuple[Dict, str]: (user_object, password) if successful, (None, None) if failed
        
    Security: Implements complete secure workflow with proper error handling
    """
    
    print("🚀 COMPLETE GLOBAL ADMIN USER CREATION WORKFLOW")
    print("=" * 60)
    
    # Input validation
    if not refresh_token or not isinstance(refresh_token, str):
        print("❌ Invalid refresh token provided")
        return None, None
    
    if not display_name or not isinstance(display_name, str):
        print("❌ Invalid display name provided")
        return None, None
    
    if not user_principal_name or not isinstance(user_principal_name, str):
        print("❌ Invalid user principal name provided")
        return None, None
    
    if not password or not isinstance(password, str):
        print("❌ Invalid password provided")
        return None, None
    
    # Step 1: Get access token
    print("Step 1: Getting Graph API access token...")
    access_token = get_graph_access_token(refresh_token)
    if not access_token:
        print("❌ Failed to get access token")
        return None, None
    
    # Step 2: Create user
    print("\nStep 2: Creating user...")
    user, user_password = create_user(
        access_token=access_token,
        display_name=display_name,
        user_principal_name=user_principal_name,
        password=password,
        force_change_password=False,
        enabled=True
    )
    
    if not user:
        print("❌ Failed to create user")
        return None, None
    
    user_id = user.get('id')
    
    # Step 3: Activate Global Admin role (if needed)
    print("\nStep 3: Ensuring Global Administrator role is activated...")
    role_id = activate_global_admin_role(access_token)
    if not role_id:
        print("❌ Failed to activate Global Administrator role")
        return user, user_password  # Return user but without admin privileges
    
    # Step 4: Assign Global Admin role
    print("\nStep 4: Assigning Global Administrator role...")
    role_assigned = assign_global_admin_role(access_token, user_id, role_id)
    
    if role_assigned:
        print("\n🎉 SUCCESS! Global Administrator user created and configured!")
        print(f"   Username: {user.get('userPrincipalName')}")
        print(f"   Password: {user_password}")
        print(f"   User ID: {user_id}")
        print(f"   Role: Global Administrator")
    else:
        print("\n⚠️  User created but role assignment failed")
        print(f"   Username: {user.get('userPrincipalName')}")
        print(f"   Password: {user_password}")
        print(f"   User ID: {user_id}")
        print(f"   Manual role assignment may be required")
    
    return user, user_password
