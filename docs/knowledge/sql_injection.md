"""VulnPilot RAG Knowledge Base — SQL Injection remediation guidance."""

# Remediation: SQL Injection
## Class
SQL Injection (CWE-89)

## Description
SQL injection occurs when untrusted data is sent to an interpreter as part of a command or query.
An attacker can use SQL injection to bypass authentication, exfiltrate data, or execute arbitrary commands.

## Common Packages / Scenarios
- Any application connecting to a relational database (PostgreSQL, MySQL, SQLite, MSSQL)
- Python: `psycopg2`, `pymysql`, `sqlite3` used with string formatting
- Java: JDBC with string concatenation
- PHP: `mysql_query()` with raw input

## Remediation Steps
1. **Use parameterised queries (prepared statements)** — never concatenate user input into SQL.
2. **Use an ORM** (SQLAlchemy, Django ORM, Hibernate) that handles escaping by default.
3. **Input validation**: whitelist expected types and lengths.
4. **Least privilege**: database user should have only SELECT/INSERT on required tables.
5. **WAF**: deploy a Web Application Firewall as a secondary control.

## Example Fix (Python / psycopg2)
```python
# VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")

# SAFE
cursor.execute("SELECT * FROM users WHERE name = %s", (user_input,))
```

## References
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
