# Security: Reference Implementation vs. Production

This reference implementation prioritizes demonstrating federated governance
patterns. Several security configurations are appropriate for development but
**must be hardened before production deployment**.

## What This Reference Implementation Does Right

- No hardcoded credentials in source code (all via `.env`)
- `.env` file restricted to mode 600 and gitignored
- SQL injection prevention via `validate_identifier()` and `validate_row_filter_expr()`
- No secrets logged (verified by audit)
- No containers run as root
- Ranger audit trail enabled (Solr)
- Safe-by-default architecture: sync gap creates noise, not risk

## Production Hardening Checklist

### Authentication (Currently: Anonymous)

Trino accepts unauthenticated connections. Ranger policies provide authorization
but not authentication.

**Production fix:**
```properties
# config.properties
http-server.authentication.type=OAUTH2
# or LDAP, KERBEROS — choose based on your IdP
```

### TLS/HTTPS (Currently: HTTP)

All inter-service communication uses plaintext HTTP.

**Production fix:**
- Enable HTTPS on Trino (`http-server.https.enabled=true`)
- Enable HTTPS on Ranger (configure TLS in `ranger-admin-site.xml`)
- Use mTLS between services or overlay network encryption

### Credential Management (Currently: Environment Variables)

AWS access keys, database passwords, and API tokens are passed as environment
variables via `.env`.

**Production fix:**
- Use **IAM instance roles** on EC2 (eliminates static AWS keys)
- Use **AWS Secrets Manager** or **HashiCorp Vault** for database passwords
- Use **Docker secrets** instead of environment variables
- Rotate credentials on a schedule

### Network Isolation (Currently: Ports on 0.0.0.0)

Gravitino (8090), Ranger (6080), and Trino (8080) bind to all interfaces.

**Production fix:**
```yaml
# docker-compose.yml — bind to localhost only
ports:
  - "127.0.0.1:8080:8080"  # Trino
  - "127.0.0.1:6080:6080"  # Ranger
  - "127.0.0.1:8090:8090"  # Gravitino
```

Or use a reverse proxy (nginx/envoy) with TLS termination for external access.
AWS security groups provide the current perimeter defense on EC2.

### User Management (Currently: Ranger-Local Users)

Users (`test_user`, `restricted_user`) are created directly in Ranger.

**Production fix:**
- Configure Ranger UserSync with Active Directory or LDAP
- Map AD groups to Ranger roles
- Remove Ranger-local user auto-provisioning

### Ranger Admin Password

The `RANGER_ADMIN_PASSWORD` is set via `.env` without strength enforcement.

**Production fix:**
- Enforce minimum 16-character passwords
- Use secrets manager for the admin password
- Audit Ranger admin access

### Database Security (Currently: SSL Disabled)

The Gravitino-to-MySQL JDBC connection uses `useSSL=false`.

**Production fix:**
```
jdbc:mysql://mysql:3306/gravitino?useSSL=true&requireSSL=true
```

## Threat Model

The safe-by-default architecture provides defense in depth:

| Threat | Mitigation |
|--------|-----------|
| Stale Ranger allow (over-permissive) | Platform-native enforcement is the backstop |
| Stale Ranger deny (under-permissive) | User blocked until sync — fail-closed |
| Ranger compromise | Platform-native enforcement remains intact |
| Trino compromise | Source platform credentials limit blast radius |
| Network eavesdropping | Requires TLS (see hardening checklist above) |
| Credential theft | Requires secrets management (see above) |

## Dependency Security

Run periodic vulnerability scans:

```bash
pip install pip-audit
pip-audit
```

All dependencies use version constraints and are actively maintained. No known
critical vulnerabilities as of the last audit.
