"""
MistWalker Integration Module

Provides Click-based CLI integration for MistWalker functionality within MistWalker.
This module wraps the MistWalker core functions with Click commands and integrates
with the token management system.
"""

import click
import sys
import secrets
import string
from typing import Optional

# Import Entra ID core functions
from .entra.core import (
    get_graph_access_token,
    create_user,
    create_global_admin_user,
    activate_global_admin_role,
    assign_global_admin_role,
    list_global_admins,
    promote_user_to_global_admin,
    demote_user_from_global_admin,
    delete_user
)


def get_effective_tenant(tenant: Optional[str], config_manager) -> str:
    """
    Get the effective tenant to use, falling back to configured default
    
    Args:
        tenant (str, optional): Explicitly provided tenant
        config_manager: Configuration manager instance
        
    Returns:
        str: Effective tenant to use
    """
    if tenant:
        return tenant
    
    if config_manager:
        default_tenant = config_manager.get('default_tenant', 'global', 'default')
        return default_tenant
    
    return 'default'


def generate_secure_password(length: int = 16) -> str:
    """
    Generate a cryptographically secure password
    
    Args:
        length (int): Password length (minimum 12)
        
    Returns:
        str: Secure password
        
    Security: Uses secrets module for cryptographically secure random generation
    """
    if length < 12:
        length = 12
    
    # Character sets for password generation
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*"
    
    # Ensure at least one character from each set
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    # Fill the rest with random characters from all sets
    all_chars = lowercase + uppercase + digits + special
    for _ in range(length - 4):
        password.append(secrets.choice(all_chars))
    
    # Shuffle the password list
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)


@click.command()
@click.option('-r', '--refresh-token', 'refresh_token', 
              help='Refresh token for Graph API access (or use stored token)')
@click.option('-u', '--username', 'username', required=True,
              help='Username for the new Global Administrator (e.g., admin@domain.com)')
@click.option('-p', '--password', 'password',
              help='Password for the new user (auto-generated if not provided)')
@click.option('-d', '--display-name', 'display_name',
              help='Display name for the user (defaults to username prefix)')
@click.option('-t', '--tenant', 'tenant', 
              help='Tenant identifier for token lookup (uses configured default if not specified)')
@click.option('--force-change-password', is_flag=True,
              help='Force password change on next sign-in')
@click.option('--generate-password', is_flag=True,
              help='Generate a secure password automatically')
@click.pass_context
def create_admin(ctx, refresh_token, username, password, display_name, tenant, 
                force_change_password, generate_password):
    """
    Create a new Global Administrator user in Entra ID
    
    This command creates a new user and assigns the Global Administrator role.
    
    Examples:
        mistwalker entra create-admin -u admin@corp.com -p "SecurePass123!"
        mistwalker entra create-admin -u admin@corp.com --generate-password
        mistwalker entra create-admin -r "refresh_token" -u admin@corp.com -p "Pass123!"
    """
    
    # Get token manager from context
    token_manager = ctx.obj.get('token_manager')
    config_manager = ctx.obj.get('config_manager')
    
    # Get effective tenant (use configured default if not specified)
    tenant = get_effective_tenant(tenant, config_manager)
    
    # Set display name if not provided
    if not display_name:
        display_name = username.split('@')[0].replace('.', ' ').replace('_', ' ').replace('-', ' ').title()
    
    # Handle password generation or validation
    if generate_password:
        password = generate_secure_password()
        click.echo(f"🔐 Generated secure password: {password}")
    elif not password:
        if click.confirm("No password provided. Generate a secure password?"):
            password = generate_secure_password()
            click.echo(f"🔐 Generated secure password: {password}")
        else:
            password = click.prompt("Enter password", hide_input=True, confirmation_prompt=True)
    
    # Get refresh token
    if not refresh_token and token_manager:
        refresh_token = token_manager.get_refresh_token(tenant)
        if refresh_token:
            click.echo(f"✅ Using stored refresh token for tenant: {tenant}")
        else:
            click.echo(f"❌ No stored refresh token found for tenant: {tenant}")
            click.echo("   Use 'mistwalker auth' to acquire tokens or provide -r/--refresh-token")
            sys.exit(1)
    elif not refresh_token:
        click.echo("❌ No refresh token provided and token manager not available")
        click.echo("   Provide refresh token with -r/--refresh-token")
        sys.exit(1)
    
    # Apply configuration defaults
    if config_manager:
        mistwalker_config = config_manager.get_entra_config(tenant)
        if not force_change_password:
            force_change_password = mistwalker_config.get('force_change_password', False)
    
    click.echo(f"🔐 Creating Global Administrator: {username}")
    click.echo("=" * 50)
    
    try:
        # Create the global admin user
        user, user_password = create_global_admin_user(
            refresh_token=refresh_token,
            display_name=display_name,
            user_principal_name=username,
            password=password
        )
        
        if user and user_password:
            click.echo("\n" + "=" * 50)
            click.echo("✅ SUCCESS! Global Administrator created:")
            click.echo(f"   Username: {user['userPrincipalName']}")
            click.echo(f"   Password: {password}")
            click.echo(f"   Display Name: {user['displayName']}")
            click.echo(f"   User ID: {user['id']}")
            click.echo(f"   Status: {'Enabled' if user.get('accountEnabled') else 'Disabled'}")
            click.echo(f"   Role: Global Administrator")
        else:
            click.echo("\n❌ Failed to create Global Administrator")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"\n❌ Error: {e}")
        sys.exit(1)


@click.command()
@click.option('-r', '--refresh-token', 'refresh_token',
              help='Refresh token for Graph API access (or use stored token)')
@click.option('-u', '--username', 'username', required=True,
              help='Username to create (e.g., user@domain.com)')
@click.option('-p', '--password', 'password',
              help='Password for the new user (auto-generated if not provided)')
@click.option('-d', '--display-name', 'display_name',
              help='Display name (defaults to username prefix)')
@click.option('-t', '--tenant', 'tenant', default='default',
              help='Tenant identifier for token lookup')
@click.option('--force-change-password', is_flag=True,
              help='Force password change on next sign-in')
@click.option('--generate-password', is_flag=True,
              help='Generate a secure password automatically')
@click.pass_context
def create_user_cmd(ctx, refresh_token, username, password, display_name, tenant, 
                   force_change_password, generate_password):
    """
    Create a new regular user (without admin privileges)
    
    Examples:
        mistwalker entra create-user -u user@corp.com -p "UserPass123!"
        mistwalker entra create-user -u user@corp.com --generate-password
    """
    
    # Get token manager from context
    token_manager = ctx.obj.get('token_manager')
    config_manager = ctx.obj.get('config_manager')
    
    # Set display name if not provided
    if not display_name:
        display_name = username.split('@')[0].replace('.', ' ').replace('_', ' ').replace('-', ' ').title()
    
    # Handle password generation or validation
    if generate_password:
        password = generate_secure_password()
        click.echo(f"🔐 Generated secure password: {password}")
    elif not password:
        if click.confirm("No password provided. Generate a secure password?"):
            password = generate_secure_password()
            click.echo(f"🔐 Generated secure password: {password}")
        else:
            password = click.prompt("Enter password", hide_input=True, confirmation_prompt=True)
    
    # Get refresh token
    if not refresh_token and token_manager:
        refresh_token = token_manager.get_refresh_token(tenant)
        if refresh_token:
            click.echo(f"✅ Using stored refresh token for tenant: {tenant}")
        else:
            click.echo(f"❌ No stored refresh token found for tenant: {tenant}")
            sys.exit(1)
    elif not refresh_token:
        click.echo("❌ No refresh token provided")
        sys.exit(1)
    
    # Apply configuration defaults
    enabled = True
    if config_manager:
        mistwalker_config = config_manager.get_entra_config(tenant)
        if not force_change_password:
            force_change_password = mistwalker_config.get('force_change_password', False)
        enabled = mistwalker_config.get('default_user_enabled', True)
    
    click.echo(f"👤 Creating user: {username}")
    click.echo("=" * 40)
    
    try:
        # Get access token
        access_token = get_graph_access_token(refresh_token)
        if not access_token:
            click.echo("❌ Failed to get access token")
            sys.exit(1)
        
        # Create user
        user, user_password = create_user(
            access_token=access_token,
            display_name=display_name,
            user_principal_name=username,
            password=password,
            force_change_password=force_change_password,
            enabled=enabled
        )
        
        if user:
            click.echo("\n" + "=" * 40)
            click.echo("✅ USER CREATED:")
            click.echo(f"   Username: {user['userPrincipalName']}")
            click.echo(f"   Password: {password}")
            click.echo(f"   Display Name: {user['displayName']}")
            click.echo(f"   User ID: {user['id']}")
            click.echo(f"   Admin Role: No")
        else:
            click.echo("❌ Failed to create user")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(1)


@click.command()
@click.option('-r', '--refresh-token', 'refresh_token',
              help='Refresh token for Graph API access (or use stored token)')
@click.option('-u', '--user', 'user', required=True,
              help='User ID or UPN to promote (e.g., user@domain.com)')
@click.option('-t', '--tenant', 'tenant', default='default',
              help='Tenant identifier for token lookup')
@click.pass_context
def promote_user(ctx, refresh_token, user, tenant):
    """
    Promote an existing user to Global Administrator
    
    Examples:
        mistwalker entra promote-user -u user@corp.com
        mistwalker entra promote-user -u c38e5999-6872-4853-8721-a63b4bc5c28c
    """
    
    # Get token manager from context
    token_manager = ctx.obj.get('token_manager')
    
    # Get refresh token
    if not refresh_token and token_manager:
        refresh_token = token_manager.get_refresh_token(tenant)
        if refresh_token:
            click.echo(f"✅ Using stored refresh token for tenant: {tenant}")
        else:
            click.echo(f"❌ No stored refresh token found for tenant: {tenant}")
            sys.exit(1)
    elif not refresh_token:
        click.echo("❌ No refresh token provided")
        sys.exit(1)
    
    click.echo(f"⬆️ Promoting user to Global Administrator: {user}")
    click.echo("=" * 50)
    
    try:
        # Get access token
        access_token = get_graph_access_token(refresh_token)
        if not access_token:
            click.echo("❌ Failed to get access token")
            sys.exit(1)
        
        # Promote user
        success = promote_user_to_global_admin(access_token, user)
        
        if success:
            click.echo("\n" + "=" * 50)
            click.echo("✅ USER PROMOTED TO GLOBAL ADMINISTRATOR")
            click.echo(f"   User: {user}")
            click.echo(f"   Role: Global Administrator")
        else:
            click.echo("\n❌ Failed to promote user")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(1)


@click.command()
@click.option('-r', '--refresh-token', 'refresh_token',
              help='Refresh token for Graph API access (or use stored token)')
@click.option('-u', '--user', 'user', required=True,
              help='User ID or UPN to demote (e.g., user@domain.com)')
@click.option('-t', '--tenant', 'tenant', default='default',
              help='Tenant identifier for token lookup')
@click.pass_context
def demote_user(ctx, refresh_token, user, tenant):
    """
    Remove Global Administrator role from a user
    
    Examples:
        mistwalker entra demote-user -u user@corp.com
        mistwalker entra demote-user -u c38e5999-6872-4853-8721-a63b4bc5c28c
    """
    
    # Get token manager from context
    token_manager = ctx.obj.get('token_manager')
    
    # Get refresh token
    if not refresh_token and token_manager:
        refresh_token = token_manager.get_refresh_token(tenant)
        if refresh_token:
            click.echo(f"✅ Using stored refresh token for tenant: {tenant}")
        else:
            click.echo(f"❌ No stored refresh token found for tenant: {tenant}")
            sys.exit(1)
    elif not refresh_token:
        click.echo("❌ No refresh token provided")
        sys.exit(1)
    
    click.echo(f"⬇️ Removing Global Administrator role from: {user}")
    click.echo("=" * 50)
    
    try:
        # Get access token
        access_token = get_graph_access_token(refresh_token)
        if not access_token:
            click.echo("❌ Failed to get access token")
            sys.exit(1)
        
        # Demote user
        success = demote_user_from_global_admin(access_token, user)
        
        if success:
            click.echo("\n" + "=" * 50)
            click.echo("✅ GLOBAL ADMINISTRATOR ROLE REMOVED")
            click.echo(f"   User: {user}")
            click.echo(f"   Former Role: Global Administrator")
            click.echo(f"   Current Status: Regular User")
        else:
            click.echo("\n❌ Failed to remove Global Administrator role")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(1)


@click.command()
@click.option('-r', '--refresh-token', 'refresh_token',
              help='Refresh token for Graph API access (or use stored token)')
@click.option('-u', '--user', 'user', required=True,
              help='User ID or UPN to delete (e.g., user@domain.com)')
@click.option('-t', '--tenant', 'tenant', default='default',
              help='Tenant identifier for token lookup')
@click.option('--confirm', is_flag=True,
              help='Skip confirmation prompt (use with caution)')
@click.pass_context
def delete_user_cmd(ctx, refresh_token, user, tenant, confirm):
    """
    Delete a user from Entra ID (removes admin roles first)
    
    WARNING: This action cannot be undone!
    
    Examples:
        mistwalker entra delete-user -u user@corp.com
        mistwalker entra delete-user -u user@corp.com --confirm
    """
    
    # Get token manager from context
    token_manager = ctx.obj.get('token_manager')
    
    # Safety confirmation unless --confirm flag is used
    if not confirm:
        click.echo(f"⚠️  WARNING: This will permanently delete the user: {user}")
        click.echo("   This action cannot be undone!")
        click.echo("   If the user has Global Administrator privileges, they will be removed first.")
        
        if not click.confirm("\nDo you want to continue?"):
            click.echo("❌ User deletion cancelled")
            return
    
    # Get refresh token
    if not refresh_token and token_manager:
        refresh_token = token_manager.get_refresh_token(tenant)
        if refresh_token:
            click.echo(f"✅ Using stored refresh token for tenant: {tenant}")
        else:
            click.echo(f"❌ No stored refresh token found for tenant: {tenant}")
            sys.exit(1)
    elif not refresh_token:
        click.echo("❌ No refresh token provided")
        sys.exit(1)
    
    click.echo(f"🗑️ Deleting user: {user}")
    click.echo("=" * 50)
    
    try:
        # Get access token
        access_token = get_graph_access_token(refresh_token)
        if not access_token:
            click.echo("❌ Failed to get access token")
            sys.exit(1)
        
        # Delete user
        success = delete_user(access_token, user)
        
        if success:
            click.echo("\n" + "=" * 50)
            click.echo("✅ USER DELETED SUCCESSFULLY")
            click.echo(f"   User: {user}")
            click.echo(f"   Status: Permanently removed from Entra ID")
            click.echo("   All roles and permissions have been revoked")
        else:
            click.echo("\n❌ Failed to delete user")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(1)


@click.command()
@click.option('-r', '--refresh-token', 'refresh_token',
              help='Refresh token for Graph API access (or use stored token)')
@click.option('-t', '--tenant', 'tenant', default='default',
              help='Tenant identifier for token lookup')
@click.pass_context
def list_admins(ctx, refresh_token, tenant):
    """
    List all Global Administrator users
    
    Examples:
        mistwalker entra list-admins
        mistwalker entra list-admins -t corp.com
    """
    
    # Get token manager from context
    token_manager = ctx.obj.get('token_manager')
    
    # Get refresh token
    if not refresh_token and token_manager:
        refresh_token = token_manager.get_refresh_token(tenant)
        if refresh_token:
            click.echo(f"✅ Using stored refresh token for tenant: {tenant}")
        else:
            click.echo(f"❌ No stored refresh token found for tenant: {tenant}")
            sys.exit(1)
    elif not refresh_token:
        click.echo("❌ No refresh token provided")
        sys.exit(1)
    
    click.echo("👑 Listing Global Administrator users")
    click.echo("=" * 40)
    
    try:
        # Get access token
        access_token = get_graph_access_token(refresh_token)
        if not access_token:
            click.echo("❌ Failed to get access token")
            sys.exit(1)
        
        # List Global Admins
        admins = list_global_admins(access_token)
        
        if admins is None:
            click.echo("❌ Failed to list Global Administrators")
            sys.exit(1)
        elif len(admins) == 0:
            click.echo("📭 No Global Administrators found")
        else:
            click.echo(f"\n📊 Summary: {len(admins)} Global Administrator(s) found")
            
    except Exception as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(1)


@click.command()
@click.option('-r', '--refresh-token', 'refresh_token',
              help='Refresh token for Graph API access (or use stored token)')
@click.option('-t', '--tenant', 'tenant', default='default',
              help='Tenant identifier for token lookup')
@click.pass_context
def test_token(ctx, refresh_token, tenant):
    """
    Test if the refresh token is valid and can access Graph API
    
    Examples:
        mistwalker entra test-token
        mistwalker entra test-token -r "refresh_token_here"
    """
    
    # Get token manager from context
    token_manager = ctx.obj.get('token_manager')
    
    # Get refresh token
    if not refresh_token and token_manager:
        refresh_token = token_manager.get_refresh_token(tenant)
        if refresh_token:
            click.echo(f"✅ Using stored refresh token for tenant: {tenant}")
        else:
            click.echo(f"❌ No stored refresh token found for tenant: {tenant}")
            sys.exit(1)
    elif not refresh_token:
        click.echo("❌ No refresh token provided")
        sys.exit(1)
    
    click.echo("🔍 Testing refresh token...")
    
    try:
        access_token = get_graph_access_token(refresh_token)
        if access_token:
            click.echo("✅ Token is valid!")
            
            # Test Graph API access
            import requests
            headers = {'Authorization': f'Bearer {access_token}'}
            try:
                response = requests.get('https://graph.microsoft.com/v1.0/me', 
                                      headers=headers, timeout=10, verify=True)
                if response.status_code == 200:
                    user_info = response.json()
                    click.echo(f"   Current User: {user_info.get('displayName')} ({user_info.get('userPrincipalName')})")
                    click.echo(f"   User ID: {user_info.get('id')}")
                else:
                    click.echo(f"⚠️  Token valid but limited access: {response.status_code}")
            except Exception as e:
                click.echo(f"⚠️  Token valid but test failed: {e}")
        else:
            click.echo("❌ Token is invalid or expired")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(1)


# Create command group for MistWalker integration
@click.group()
def mistwalker_group():
    """MistWalker Entra ID management commands"""
    pass


# Add commands to the group
mistwalker_group.add_command(create_admin, name='create-admin')
mistwalker_group.add_command(create_user_cmd, name='create-user')
mistwalker_group.add_command(promote_user, name='promote-user')
mistwalker_group.add_command(demote_user, name='demote-user')
mistwalker_group.add_command(delete_user_cmd, name='delete-user')
mistwalker_group.add_command(list_admins, name='list-admins')
mistwalker_group.add_command(test_token, name='test-token')

# Export the main command for use in main.py
mistwalker_cli = mistwalker_group
