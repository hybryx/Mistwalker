"""
Configuration Manager

Handles configuration file management for MistWalker, supporting both
global settings and tenant-specific configurations.

Security Note: Configuration files may contain sensitive information.
Ensure proper file permissions and secure storage practices.
"""

import json
import os
import yaml
from typing import Dict, Any, Optional
import stat


class ConfigManager:
    """
    Manages configuration files and settings for MistWalker
    
    Supports both JSON and YAML configuration formats with secure file handling.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize ConfigManager
        
        Args:
            config_path (str, optional): Path to configuration file
        """
        self.config_path = config_path
        self.config_data = {}
        self.default_config = {
            'global': {
                'debug': False,
                'no_color': False,
                'default_tenant': 'default',
                'cache_tokens': False,
                'token_cache_dir': None
            },
            'seamlesspass': {
                'resource': 'https://graph.windows.net',
                'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
                'spn': 'HTTP/autologon.microsoftazuread-sso.com',
                'ignore_sso_check': False
            },
            'foghorn': {
                'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
                'force_change_password': False,
                'default_user_enabled': True
            },
            'tenants': {}
        }
        
        # Load configuration if path provided
        if self.config_path:
            self.load_config()
    
    def load_config(self, config_path: Optional[str] = None) -> bool:
        """
        Load configuration from file
        
        Args:
            config_path (str, optional): Override config file path
            
        Returns:
            bool: True if successful, False otherwise
        """
        if config_path:
            self.config_path = config_path
        
        if not self.config_path or not os.path.exists(self.config_path):
            # Use default configuration
            self.config_data = self.default_config.copy()
            return False
        
        try:
            with open(self.config_path, 'r') as f:
                if self.config_path.endswith('.yaml') or self.config_path.endswith('.yml'):
                    loaded_config = yaml.safe_load(f)
                else:
                    loaded_config = json.load(f)
            
            # Merge with defaults
            self.config_data = self._merge_configs(self.default_config, loaded_config)
            return True
            
        except Exception as e:
            print(f"⚠️  Failed to load config from {self.config_path}: {e}")
            self.config_data = self.default_config.copy()
            return False
    
    def save_config(self, config_path: Optional[str] = None) -> bool:
        """
        Save configuration to file
        
        Args:
            config_path (str, optional): Override config file path
            
        Returns:
            bool: True if successful, False otherwise
        """
        if config_path:
            self.config_path = config_path
        
        if not self.config_path:
            print("❌ No config path specified")
            return False
        
        try:
            # Ensure directory exists
            config_dir = os.path.dirname(self.config_path)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir, mode=0o700)
            
            # Write configuration file
            with open(self.config_path, 'w') as f:
                if self.config_path.endswith('.yaml') or self.config_path.endswith('.yml'):
                    yaml.safe_dump(self.config_data, f, default_flow_style=False, indent=2)
                else:
                    json.dump(self.config_data, f, indent=2)
            
            # Set secure file permissions (owner read/write only)
            os.chmod(self.config_path, stat.S_IRUSR | stat.S_IWUSR)
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to save config to {self.config_path}: {e}")
            return False
    
    def get(self, key: str, section: str = 'global', default: Any = None) -> Any:
        """
        Get configuration value
        
        Args:
            key (str): Configuration key
            section (str): Configuration section
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        section_data = self.config_data.get(section, {})
        return section_data.get(key, default)
    
    def set(self, key: str, value: Any, section: str = 'global') -> None:
        """
        Set configuration value
        
        Args:
            key (str): Configuration key
            value: Configuration value
            section (str): Configuration section
        """
        if section not in self.config_data:
            self.config_data[section] = {}
        
        self.config_data[section][key] = value
    
    def get_tenant_config(self, tenant: str) -> Dict[str, Any]:
        """
        Get tenant-specific configuration
        
        Args:
            tenant (str): Tenant identifier
            
        Returns:
            dict: Tenant configuration
        """
        tenants = self.config_data.get('tenants', {})
        return tenants.get(tenant, {})
    
    def set_tenant_config(self, tenant: str, config: Dict[str, Any]) -> None:
        """
        Set tenant-specific configuration
        
        Args:
            tenant (str): Tenant identifier
            config (dict): Tenant configuration
        """
        if 'tenants' not in self.config_data:
            self.config_data['tenants'] = {}
        
        self.config_data['tenants'][tenant] = config
    
    def get_seamlesspass_config(self, tenant: str = None) -> Dict[str, Any]:
        """
        Get SeamlessPass configuration with tenant overrides
        
        Args:
            tenant (str, optional): Tenant identifier for overrides
            
        Returns:
            dict: SeamlessPass configuration
        """
        base_config = self.config_data.get('seamlesspass', {}).copy()
        
        if tenant:
            tenant_config = self.get_tenant_config(tenant)
            seamlesspass_overrides = tenant_config.get('seamlesspass', {})
            base_config.update(seamlesspass_overrides)
        
        return base_config
    
    def get_foghorn_config(self, tenant: str = None) -> Dict[str, Any]:
        """
        Get Foghorn configuration with tenant overrides
        
        Args:
            tenant (str, optional): Tenant identifier for overrides
            
        Returns:
            dict: Foghorn configuration
        """
        base_config = self.config_data.get('foghorn', {}).copy()
        
        if tenant:
            tenant_config = self.get_tenant_config(tenant)
            foghorn_overrides = tenant_config.get('foghorn', {})
            base_config.update(foghorn_overrides)
        
        return base_config
    
    def create_sample_config(self, config_path: str) -> bool:
        """
        Create a sample configuration file
        
        Args:
            config_path (str): Path for sample config file
            
        Returns:
            bool: True if successful, False otherwise
        """
        sample_config = {
            'global': {
                'debug': False,
                'no_color': False,
                'default_tenant': 'corp.com',
                'cache_tokens': True,
                'token_cache_dir': '~/.mistwalker/tokens'
            },
            'seamlesspass': {
                'resource': 'https://graph.windows.net',
                'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
                'spn': 'HTTP/autologon.microsoftazuread-sso.com',
                'ignore_sso_check': False
            },
            'foghorn': {
                'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
                'force_change_password': False,
                'default_user_enabled': True
            },
            'tenants': {
                'corp.com': {
                    'domain': 'corp.local',
                    'dc_host': 'dc.corp.local',
                    'seamlesspass': {
                        'resource': 'https://graph.microsoft.com'
                    },
                    'foghorn': {
                        'force_change_password': True
                    }
                },
                'test.onmicrosoft.com': {
                    'domain': 'test.local',
                    'dc_host': '10.0.1.2'
                }
            }
        }
        
        try:
            # Ensure directory exists
            config_dir = os.path.dirname(config_path)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir, mode=0o700)
            
            # Write sample configuration
            with open(config_path, 'w') as f:
                if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                    yaml.safe_dump(sample_config, f, default_flow_style=False, indent=2)
                else:
                    json.dump(sample_config, f, indent=2)
            
            # Set secure file permissions
            os.chmod(config_path, stat.S_IRUSR | stat.S_IWUSR)
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to create sample config: {e}")
            return False
    
    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively merge configuration dictionaries
        
        Args:
            base (dict): Base configuration
            override (dict): Override configuration
            
        Returns:
            dict: Merged configuration
        """
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def validate_config(self) -> tuple[bool, list]:
        """
        Validate configuration structure and values
        
        Returns:
            tuple: (is_valid, list_of_errors)
        """
        errors = []
        
        # Check required sections
        required_sections = ['global', 'seamlesspass', 'foghorn']
        for section in required_sections:
            if section not in self.config_data:
                errors.append(f"Missing required section: {section}")
        
        # Validate seamlesspass section
        seamlesspass_config = self.config_data.get('seamlesspass', {})
        if 'client_id' in seamlesspass_config:
            client_id = seamlesspass_config['client_id']
            if not isinstance(client_id, str) or len(client_id) != 36:
                errors.append("Invalid client_id format in seamlesspass section")
        
        # Validate tenant configurations
        tenants = self.config_data.get('tenants', {})
        for tenant_name, tenant_config in tenants.items():
            if not isinstance(tenant_config, dict):
                errors.append(f"Invalid tenant configuration for: {tenant_name}")
        
        return len(errors) == 0, errors
    
    def get_all_config(self) -> Dict[str, Any]:
        """
        Get complete configuration data
        
        Returns:
            dict: Complete configuration
        """
        return self.config_data.copy()
    
    def reset_to_defaults(self) -> None:
        """Reset configuration to default values"""
        self.config_data = self.default_config.copy()
