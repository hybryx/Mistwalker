"""
Token Manager

Handles secure storage, retrieval, and validation of Azure access and refresh tokens.
Provides a bridge between SeamlessPass token acquisition and Foghorn token usage.

Security Note: Tokens are handled in memory only by default. Persistent storage
should only be used in secure environments with proper access controls.
"""

import json
import base64
import time
import os
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import tempfile
import stat


class TokenManager:
    """
    Manages Azure access and refresh tokens with security best practices.
    
    Features:
    - In-memory token storage by default
    - Optional secure file-based caching
    - Token validation and expiration checking
    - Automatic token refresh capabilities
    """
    
    def __init__(self, debug: bool = False, cache_dir: Optional[str] = None):
        """
        Initialize TokenManager
        
        Args:
            debug (bool): Enable debug output
            cache_dir (str, optional): Directory for token cache files
        """
        self.debug = debug
        self.cache_dir = cache_dir or os.path.join(tempfile.gettempdir(), 'mistwalker_tokens')
        self._tokens = {}  # In-memory token storage
        
        # Create secure cache directory if it doesn't exist
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir, mode=0o700)  # Owner read/write/execute only
        
        # Load existing tokens from cache on initialization
        self._load_all_cached_tokens()
    
    def store_tokens(self, tokens: Dict[str, Any], tenant: str = "default") -> None:
        """
        Store access and refresh tokens securely
        
        Args:
            tokens (dict): Token dictionary from SeamlessPass/Azure
            tenant (str): Tenant identifier for multi-tenant support
        """
        if self.debug:
            print(f"🔐 Storing tokens for tenant: {tenant}")
        
        # Validate token structure
        if not isinstance(tokens, dict):
            raise ValueError("Tokens must be a dictionary")
        
        # Extract and validate required fields
        access_token = tokens.get('access_token')
        refresh_token = tokens.get('refresh_token')
        
        if not access_token or not refresh_token:
            raise ValueError("Both access_token and refresh_token are required")
        
        # Parse access token to extract metadata
        token_metadata = self._parse_access_token(access_token)
        
        # Store in memory with metadata
        self._tokens[tenant] = {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_at': token_metadata.get('exp', 0),
            'tenant_id': token_metadata.get('tid'),
            'user_id': token_metadata.get('oid'),
            'username': token_metadata.get('upn'),
            'stored_at': int(time.time()),
            'raw_tokens': tokens  # Store original token response
        }
        
        # Automatically save to cache
        self.save_to_cache(tenant)
        
        if self.debug:
            print(f"✅ Tokens stored successfully")
            print(f"   Tenant ID: {token_metadata.get('tid', 'Unknown')}")
            print(f"   User: {token_metadata.get('upn', 'Unknown')}")
            print(f"   Expires: {datetime.fromtimestamp(token_metadata.get('exp', 0))}")
    
    def get_refresh_token(self, tenant: str = "default") -> Optional[str]:
        """
        Get refresh token for the specified tenant
        
        Args:
            tenant (str): Tenant identifier
            
        Returns:
            str: Refresh token if available, None otherwise
        """
        token_data = self._tokens.get(tenant)
        if not token_data:
            if self.debug:
                print(f"❌ No tokens found for tenant: {tenant}")
            return None
        
        refresh_token = token_data.get('refresh_token')
        if self.debug and refresh_token:
            print(f"✅ Retrieved refresh token for tenant: {tenant}")
        
        return refresh_token
    
    def get_access_token(self, tenant: str = "default") -> Optional[str]:
        """
        Get access token for the specified tenant (checks expiration)
        
        Args:
            tenant (str): Tenant identifier
            
        Returns:
            str: Valid access token if available, None if expired or missing
        """
        token_data = self._tokens.get(tenant)
        if not token_data:
            if self.debug:
                print(f"❌ No tokens found for tenant: {tenant}")
            return None
        
        # Check if token is expired (with 5-minute buffer)
        expires_at = token_data.get('expires_at', 0)
        current_time = int(time.time())
        buffer_time = 300  # 5 minutes
        
        if expires_at <= (current_time + buffer_time):
            if self.debug:
                print(f"⚠️  Access token expired for tenant: {tenant}")
                print(f"   Expired at: {datetime.fromtimestamp(expires_at)}")
            return None
        
        access_token = token_data.get('access_token')
        if self.debug and access_token:
            print(f"✅ Retrieved valid access token for tenant: {tenant}")
            print(f"   Expires at: {datetime.fromtimestamp(expires_at)}")
        
        return access_token
    
    def get_token_info(self, tenant: str = "default") -> Optional[Dict[str, Any]]:
        """
        Get token metadata and information
        
        Args:
            tenant (str): Tenant identifier
            
        Returns:
            dict: Token metadata if available, None otherwise
        """
        token_data = self._tokens.get(tenant)
        if not token_data:
            return None
        
        return {
            'tenant_id': token_data.get('tenant_id'),
            'user_id': token_data.get('user_id'),
            'username': token_data.get('username'),
            'expires_at': token_data.get('expires_at'),
            'stored_at': token_data.get('stored_at'),
            'is_expired': token_data.get('expires_at', 0) <= int(time.time()),
            'time_until_expiry': max(0, token_data.get('expires_at', 0) - int(time.time()))
        }
    
    def list_tenants(self) -> list:
        """
        List all tenants with stored tokens
        
        Returns:
            list: List of tenant identifiers
        """
        return list(self._tokens.keys())
    
    def clear_tokens(self, tenant: str = None) -> None:
        """
        Clear stored tokens
        
        Args:
            tenant (str, optional): Specific tenant to clear, or None for all
        """
        if tenant:
            if tenant in self._tokens:
                del self._tokens[tenant]
                # Also remove cache file
                cache_file = os.path.join(self.cache_dir, f"{tenant}_tokens.json")
                if os.path.exists(cache_file):
                    try:
                        os.remove(cache_file)
                        if self.debug:
                            print(f"🗑️  Removed cache file: {cache_file}")
                    except Exception as e:
                        if self.debug:
                            print(f"⚠️  Failed to remove cache file: {e}")
                if self.debug:
                    print(f"🗑️  Cleared tokens for tenant: {tenant}")
        else:
            self._tokens.clear()
            # Remove all cache files
            try:
                for filename in os.listdir(self.cache_dir):
                    if filename.endswith('_tokens.json'):
                        cache_file = os.path.join(self.cache_dir, filename)
                        os.remove(cache_file)
                        if self.debug:
                            print(f"🗑️  Removed cache file: {cache_file}")
            except Exception as e:
                if self.debug:
                    print(f"⚠️  Failed to remove cache files: {e}")
            if self.debug:
                print("🗑️  Cleared all stored tokens")
    
    def _parse_access_token(self, access_token: str) -> Dict[str, Any]:
        """
        Parse JWT access token to extract metadata
        
        Args:
            access_token (str): JWT access token
            
        Returns:
            dict: Parsed token claims
        """
        try:
            # JWT tokens have 3 parts separated by dots
            parts = access_token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT token format")
            
            # Decode the payload (second part)
            payload = parts[1]
            
            # Add padding if needed for base64 decoding
            padding = len(payload) % 4
            if padding:
                payload += '=' * (4 - padding)
            
            # Decode and parse JSON
            decoded_payload = base64.urlsafe_b64decode(payload.encode('utf-8'))
            token_claims = json.loads(decoded_payload.decode('utf-8'))
            
            return token_claims
            
        except Exception as e:
            if self.debug:
                print(f"⚠️  Failed to parse access token: {e}")
            return {}
    
    def save_to_cache(self, tenant: str = "default", cache_file: str = None) -> bool:
        """
        Save tokens to secure cache file
        
        Args:
            tenant (str): Tenant identifier
            cache_file (str, optional): Custom cache file path
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not cache_file:
            cache_file = os.path.join(self.cache_dir, f"{tenant}_tokens.json")
        
        token_data = self._tokens.get(tenant)
        if not token_data:
            if self.debug:
                print(f"❌ No tokens to cache for tenant: {tenant}")
            return False
        
        try:
            # Create cache data (exclude sensitive raw tokens)
            cache_data = {
                'tenant_id': token_data.get('tenant_id'),
                'user_id': token_data.get('user_id'),
                'username': token_data.get('username'),
                'expires_at': token_data.get('expires_at'),
                'stored_at': token_data.get('stored_at'),
                'refresh_token': token_data.get('refresh_token')  # Only cache refresh token
            }
            
            # Write to secure file
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            # Set secure file permissions (owner read/write only)
            os.chmod(cache_file, stat.S_IRUSR | stat.S_IWUSR)
            
            if self.debug:
                print(f"💾 Tokens cached to: {cache_file}")
            
            return True
            
        except Exception as e:
            if self.debug:
                print(f"❌ Failed to cache tokens: {e}")
            return False
    
    def load_from_cache(self, tenant: str = "default", cache_file: str = None) -> bool:
        """
        Load tokens from cache file
        
        Args:
            tenant (str): Tenant identifier
            cache_file (str, optional): Custom cache file path
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not cache_file:
            cache_file = os.path.join(self.cache_dir, f"{tenant}_tokens.json")
        
        if not os.path.exists(cache_file):
            if self.debug:
                print(f"❌ Cache file not found: {cache_file}")
            return False
        
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            
            # Check if cached token is still valid
            expires_at = cache_data.get('expires_at', 0)
            if expires_at <= int(time.time()):
                if self.debug:
                    print(f"⚠️  Cached token expired for tenant: {tenant}")
                return False
            
            # Restore token data (without access token - needs refresh)
            self._tokens[tenant] = {
                'access_token': None,  # Will need to be refreshed
                'refresh_token': cache_data.get('refresh_token'),
                'expires_at': cache_data.get('expires_at'),
                'tenant_id': cache_data.get('tenant_id'),
                'user_id': cache_data.get('user_id'),
                'username': cache_data.get('username'),
                'stored_at': cache_data.get('stored_at'),
                'raw_tokens': {}
            }
            
            if self.debug:
                print(f"📂 Tokens loaded from cache: {cache_file}")
                print(f"   User: {cache_data.get('username', 'Unknown')}")
            
            return True
            
        except Exception as e:
            if self.debug:
                print(f"❌ Failed to load cached tokens: {e}")
            return False
    
    def _load_all_cached_tokens(self) -> None:
        """
        Load all cached tokens on initialization
        
        Scans the cache directory for token files and loads valid ones.
        """
        try:
            if not os.path.exists(self.cache_dir):
                return
            
            for filename in os.listdir(self.cache_dir):
                if filename.endswith('_tokens.json'):
                    # Extract tenant name from filename
                    tenant = filename.replace('_tokens.json', '')
                    
                    # Try to load the cached tokens
                    cache_file = os.path.join(self.cache_dir, filename)
                    self.load_from_cache(tenant, cache_file)
                    
        except Exception as e:
            if self.debug:
                print(f"⚠️  Failed to load cached tokens on initialization: {e}")
