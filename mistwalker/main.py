#!/usr/bin/env python3
"""
MistWalker Main CLI Entry Point

Unified command-line interface that combines:
- SeamlessPass: Kerberos-based Azure token acquisition
- MistWalker: Entra ID user and role management

Security Note: This tool handles sensitive authentication tokens and should be used
only in authorized penetration testing or administrative contexts.
"""

import sys
import click
from typing import Optional

# Import submodules
from .seamlesspass_integration import seamlesspass_cli
from .mistwalker_integration import mistwalker_cli
from .utils.token_manager import TokenManager
from .utils.config_manager import ConfigManager


@click.group()
@click.option('--config', '-c', type=click.Path(), help='Configuration file path')
@click.option('--debug', is_flag=True, help='Enable debug output')
@click.option('--no-color', is_flag=True, help='Disable colored output')
@click.pass_context
def cli(ctx, config, debug, no_color):
    """
    MistWalker - Unified Entra ID Management Tool
    
    Combines SeamlessPass (Kerberos token acquisition) with MistWalker (Entra ID management)
    for complete Azure AD penetration testing and administration.
    
    \b
    Examples:
    \b
        # Acquire tokens using Kerberos (username/password)
        mistwalker init seamlesspass acquire -tenant corp.com -domain corp.local -dc dc.corp.local -username user -password pass
    \b
        # Acquire tokens using AZUREADSSOACC NTLM hash
        mistwalker init seamlesspass acquire -tenant corp.com -adssoacc-ntlm DEADBEEFDEADBEEFDEADBEEFDEADBEEF -user-sid S-1-5-21-1234567890-1234567890-1234567890-1234
    \b
        # List stored tokens
        mistwalker init seamlesspass list
    \b
        # Get token details
        mistwalker init seamlesspass get -t corp.com
    """
    # Ensure context object exists
    ctx.ensure_object(dict)
    
    # Store global options in context
    ctx.obj['debug'] = debug
    ctx.obj['no_color'] = no_color
    ctx.obj['config_path'] = config
    
    # Initialize configuration manager
    config_manager = ConfigManager(config_path=config)
    ctx.obj['config_manager'] = config_manager
    
    # Initialize token manager
    token_manager = TokenManager(debug=debug)
    ctx.obj['token_manager'] = token_manager


@cli.group()
@click.pass_context
def init(ctx):
    """
    Token initialization and management
    
    This command group provides token acquisition and management functionality
    for various authentication methods including SeamlessPass.
    """
    pass


@cli.group()
@click.pass_context
def entra(ctx):
    """
    Entra ID user and role management
    
    This command group provides MistWalker functionality for managing
    Entra ID users and Global Administrator roles.
    """
    pass


@cli.command()
@click.pass_context
def version(ctx):
    """Display version information"""
    from . import __version__, __author__, __description__
    
    click.echo(f"MistWalker v{__version__}")
    click.echo(f"{__description__}")
    click.echo(f"Author: {__author__}")


def main():
    """Main entry point for the CLI application"""
    try:
        # Add subcommand groups to their respective parent groups
        init.add_command(seamlesspass_cli, name='seamlesspass')
        
        # Add mistwalker commands directly to entra group (no nested structure)
        entra.add_command(mistwalker_cli.commands['create-admin'], name='create-admin')
        entra.add_command(mistwalker_cli.commands['create-user'], name='create-user')
        entra.add_command(mistwalker_cli.commands['promote-user'], name='promote-user')
        entra.add_command(mistwalker_cli.commands['demote-user'], name='demote-user')
        entra.add_command(mistwalker_cli.commands['delete-user'], name='delete-user')
        entra.add_command(mistwalker_cli.commands['list-admins'], name='list-admins')
        entra.add_command(mistwalker_cli.commands['test-token'], name='test-token')
        
        # Run the CLI
        cli()
        
    except KeyboardInterrupt:
        click.echo("\n❌ Operation cancelled by user", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
