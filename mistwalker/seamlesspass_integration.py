"""
SeamlessPass Integration Module

Provides Click-based CLI integration for SeamlessPass functionality within MistWalker.
This module wraps the original SeamlessPass argparse-based CLI with Click commands
while maintaining all original functionality and adding token management integration.
"""

import click
import sys
from typing import Optional

# Import SeamlessPass components
from .seamlesspass.main import main as seamlesspass_main
from .seamlesspass import seamlesspass
from .seamlesspass.utils.exceptions import UsageError


@click.command()
@click.option('-t', '-tenant', 'tenant', metavar='tenant domain', 
              help='Domain of the tenant (e.g. example.com, corp.onmicrosoft.com)')
@click.option('-r', '-resource', 'resource', metavar='resource URI', 
              help='Target cloud service to be accessed (Default: https://graph.windows.net)')
@click.option('-c', '-client-id', 'client_id', metavar='client_id',
              help='Microsoft 365 client ID (Default: 1b730954-1685-4b74-9bfd-dac224a7b894)')
@click.option('-ignore-sso-check', 'ignore_sso_check', is_flag=True,
              help='Try to login using Seamless SSO even if it is not enabled')
@click.option('-d', '-domain', 'domain', metavar='domain',
              help='Local domain (e.g., corp.local)')
@click.option('-dc', '-dc-ip', '-dc_host', 'dc_host', metavar='DC host/IP',
              help='Hostname or IP Address of the domain controller used for authentication')
@click.option('-u', '-username', 'username', metavar='username',
              help='Username for authentication')
@click.option('-p', '-password', 'password', metavar='password',
              help='Password for authentication')
@click.option('-n', '-ntlm', 'ntlm', metavar='[LMHASH:]NTHASH',
              help="User's NTLM hashed password, format is [LMHASH:]NTHASH")
@click.option('-aes', 'aes_key', metavar='AESKey',
              help="User's AES 128/256 key")
@click.option('-tgt', 'tgt', metavar='base64 TGT / TGT file',
              help='base64-encoded Ticket-Granting Ticket (TGT) or path to TGT file (kirbi/ccache)')
@click.option('-tgs', 'tgs', metavar='base64 TGS / TGS file',
              help='base64-encoded Service Ticket (TGS) or path to TGS file (kirbi/ccache)')
@click.option('-spn', 'spn', metavar='SPN',
              help='Target service principal name. (Default: HTTP/autologon.microsoftazuread-sso.com)')
@click.option('-domain-sid', 'domain_sid', metavar='SID',
              help='Domain Security Identifier')
@click.option('-user-rid', 'user_rid', metavar='number',
              help='User Relative ID (Last part of user SID)')
@click.option('-user-sid', 'user_sid', metavar='SID',
              help='User Security Identifier')
@click.option('-adssoacc-ntlm', 'adssoacc_ntlm', metavar='[LMHASH:]NTHASH',
              help='NTLM hash of AZUREADSSOACC account (Used to forge TGS)')
@click.option('-adssoacc-aes', 'adssoacc_aes', metavar='AESKey',
              help='AES 128/256 Key of AZUREADSSOACC account (Used to forge TGS)')
@click.option('-proxy', 'proxies', metavar='[scheme]://[user:password]@[host]:[port]',
              help='HTTP proxy for requests (example: http://burp:8080)')
@click.option('-ua', '-user-agent', 'user_agent', metavar='USERAGENT',
              help='HTTP User agent used in interaction with Microsoft 365 APIs')
@click.option('--debug', is_flag=True, help='Turn debug output on')
@click.option('--no-color', is_flag=True, help='Turn off console colors')
@click.pass_context
def acquire_command(ctx, tenant, resource, client_id, ignore_sso_check, domain, dc_host,
                    username, password, ntlm, aes_key, tgt, tgs, spn, domain_sid,
                    user_rid, user_sid, adssoacc_ntlm, adssoacc_aes, proxies,
                    user_agent, debug, no_color):
    """
    SeamlessPass - Acquire Azure tokens using Kerberos authentication
    
    Leverages Kerberos tickets to get Microsoft 365 access tokens using Seamless SSO.
    These tokens can be used for further interaction with Microsoft 365 services.
    
    Examples:
        mistwalker auth seamlesspass -tenant corp.com -domain corp.local -dc dc.corp.local -tgt <base64_TGT>
        mistwalker auth seamlesspass -tenant corp.com -tgs user_tgs.ccache
        mistwalker auth seamlesspass -tenant corp.com -domain corp.local -dc dc.corp.local -username user -password pass
    """
    
    # Get token manager from context
    token_manager = ctx.obj.get('token_manager')
    config_manager = ctx.obj.get('config_manager')
    
    # Apply configuration defaults
    if config_manager:
        seamlesspass_config = config_manager.get_seamlesspass_config(tenant)
        
        # Apply config defaults if not provided via CLI
        if not resource:
            resource = seamlesspass_config.get('resource')
        if not client_id:
            client_id = seamlesspass_config.get('client_id')
        if not spn:
            spn = seamlesspass_config.get('spn')
        if not ignore_sso_check:
            ignore_sso_check = seamlesspass_config.get('ignore_sso_check', False)
    
    # Create options object compatible with original SeamlessPass
    class Options:
        def __init__(self):
            self.tenant = tenant
            self.resource = resource
            self.client_id = client_id
            self.ignore_sso_check = ignore_sso_check
            self.domain = domain
            self.dc_host = dc_host
            self.username = username
            self.password = password
            self.ntlm = ntlm
            self.aes_key = aes_key
            self.tgt = tgt
            self.tgs = tgs
            self.spn = spn
            self.domain_sid = domain_sid
            self.user_rid = user_rid
            self.user_sid = user_sid
            self.adssoacc_ntlm = adssoacc_ntlm
            self.adssoacc_aes = adssoacc_aes
            self.proxies = proxies
            self.user_agent = user_agent
            self.debug = debug or ctx.obj.get('debug', False)
            self.no_color = no_color or ctx.obj.get('no_color', False)
    
    options = Options()
    
    # Validate required parameters
    if not options.tenant:
        click.echo("❌ Error: Tenant domain is required (-t/--tenant)", err=True)
        sys.exit(1)
    
    try:
        # Capture original stdout to intercept token output
        import io
        from contextlib import redirect_stdout, redirect_stderr
        
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        
        # Run SeamlessPass with captured output
        with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
            # Import and run seamlesspass directly
            from .seamlesspass.seamlesspass import run
            tokens = run(options)
        
        # Get captured output
        stdout_output = stdout_capture.getvalue()
        stderr_output = stderr_capture.getvalue()
        
        # Print captured output
        if stderr_output:
            click.echo(stderr_output, err=True)
        if stdout_output:
            click.echo(stdout_output)
        
        # Debug: Check what tokens were returned (only in debug mode)
        if options.debug:
            click.echo(f"🔍 DEBUG: tokens returned = {tokens}", err=True)
            click.echo(f"🔍 DEBUG: token_manager = {token_manager}", err=True)
        
        # Automatically store tokens if we have a token manager and tokens were acquired
        if token_manager and tokens:
            try:
                token_manager.store_tokens(tokens, tenant or 'default')
                click.echo(f"✅ Tokens stored in MistWalker token manager for tenant: {tenant or 'default'}")
                
                # Show token info
                token_info = token_manager.get_token_info(tenant or 'default')
                if token_info:
                    click.echo(f"   User: {token_info.get('username', 'Unknown')}")
                    click.echo(f"   Tenant ID: {token_info.get('tenant_id', 'Unknown')}")
                    
            except Exception as e:
                click.echo(f"⚠️  Failed to store tokens: {e}", err=True)
        
    except UsageError as e:
        click.echo(f"❌ Usage Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        if options.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@click.command()
@click.option('-t', '-tenant', 'tenant', required=True, metavar='tenant domain',
              help='Domain of the tenant (e.g. example.com, corp.onmicrosoft.com)')
@click.pass_context
def get_tokens(ctx, tenant):
    """
    Retrieve stored tokens for a tenant
    
    Shows token information and status for the specified tenant.
    """
    token_manager = ctx.obj.get('token_manager')
    
    if not token_manager:
        click.echo("❌ Token manager not available", err=True)
        sys.exit(1)
    
    # Get token info
    token_info = token_manager.get_token_info(tenant)
    
    if not token_info:
        click.echo(f"❌ No tokens found for tenant: {tenant}")
        sys.exit(1)
    
    # Display token information
    click.echo(f"🔐 Token Information for {tenant}")
    click.echo("=" * 50)
    click.echo(f"User: {token_info.get('username', 'Unknown')}")
    click.echo(f"Tenant ID: {token_info.get('tenant_id', 'Unknown')}")
    click.echo(f"User ID: {token_info.get('user_id', 'Unknown')}")
    
    # Check expiration status
    if token_info.get('is_expired'):
        click.echo("Status: ❌ EXPIRED")
    else:
        time_left = token_info.get('time_until_expiry', 0)
        hours = time_left // 3600
        minutes = (time_left % 3600) // 60
        click.echo(f"Status: ✅ Valid ({hours}h {minutes}m remaining)")
    
    # Show refresh token availability
    refresh_token = token_manager.get_refresh_token(tenant)
    if refresh_token:
        click.echo(f"Refresh Token: ✅ Available ({len(refresh_token)} chars)")
        click.echo(f"\nRefresh Token:")
        click.echo(refresh_token)
    else:
        click.echo("Refresh Token: ❌ Not available")


@click.command()
@click.pass_context
def list_tokens(ctx):
    """
    List all stored tokens
    
    Shows a summary of all tenants with stored tokens.
    """
    token_manager = ctx.obj.get('token_manager')
    
    if not token_manager:
        click.echo("❌ Token manager not available", err=True)
        sys.exit(1)
    
    tenants = token_manager.list_tenants()
    
    if not tenants:
        click.echo("📭 No stored tokens found")
        return
    
    click.echo(f"🔐 Stored Tokens ({len(tenants)} tenant{'s' if len(tenants) != 1 else ''})")
    click.echo("=" * 50)
    
    for i, tenant in enumerate(tenants, 1):
        token_info = token_manager.get_token_info(tenant)
        if token_info:
            status = "❌ EXPIRED" if token_info.get('is_expired') else "✅ Valid"
            username = token_info.get('username', 'Unknown')
            
            click.echo(f"{i:2d}. {tenant}")
            click.echo(f"    User: {username}")
            click.echo(f"    Status: {status}")
            
            if not token_info.get('is_expired'):
                time_left = token_info.get('time_until_expiry', 0)
                hours = time_left // 3600
                minutes = (time_left % 3600) // 60
                click.echo(f"    Expires in: {hours}h {minutes}m")
            
            click.echo()


@click.command()
@click.option('-t', '-tenant', 'tenant', metavar='tenant domain',
              help='Specific tenant to clear (clears all if not specified)')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def clear_tokens(ctx, tenant, confirm):
    """
    Clear stored tokens
    
    Removes tokens from memory. Use with caution as this cannot be undone.
    """
    token_manager = ctx.obj.get('token_manager')
    
    if not token_manager:
        click.echo("❌ Token manager not available", err=True)
        sys.exit(1)
    
    # Confirmation prompt
    if not confirm:
        if tenant:
            if not click.confirm(f"Clear tokens for tenant '{tenant}'?"):
                click.echo("❌ Operation cancelled")
                return
        else:
            if not click.confirm("Clear ALL stored tokens?"):
                click.echo("❌ Operation cancelled")
                return
    
    # Clear tokens
    token_manager.clear_tokens(tenant)
    
    if tenant:
        click.echo(f"✅ Cleared tokens for tenant: {tenant}")
    else:
        click.echo("✅ Cleared all stored tokens")


# Create command group for SeamlessPass integration
@click.group()
def seamlesspass_group():
    """SeamlessPass token acquisition commands"""
    pass


# Add commands to the group
seamlesspass_group.add_command(acquire_command, name='acquire')
seamlesspass_group.add_command(get_tokens, name='get')
seamlesspass_group.add_command(list_tokens, name='list')
seamlesspass_group.add_command(clear_tokens, name='clear')

# Export the main command for use in main.py
seamlesspass_cli = seamlesspass_group
