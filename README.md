# ezpgp

A minimal, auditable PGP encryption application for secure messaging.

## Installation

```bash
cargo install --path .
```

## Usage

Run the application:

```bash
sendpgp
```

### First Time Setup

On first run, you'll be prompted to set a password. This password encrypts your private key.

Your keys will be stored in `~/.ezpgp/`:
- `private.asc` - Your encrypted private key
- `public.asc` - Your public key (share this with contacts)
- `contacts.db` - Your contact book database

### Main Menu

1. **Encrypt message** - Encrypt a message for a contact
2. **Decrypt message** - Decrypt a received message
3. **Add contact** - Add a contact's public key
4. **Remove contact** - Remove a contact
5. **List contacts** - View all contacts with fingerprints
6. **Reset ezpgp** - Delete all keys and contacts (WARNING: irreversible)
7. **Exit** - Quit the application

### Workflow Example

**Alice wants to send an encrypted message to Bob:**

1. Alice shares her public key (`~/.ezpgp/public.asc`) with Bob
2. Bob adds Alice as a contact in his ezpgp
3. Bob shares his public key with Alice
4. Alice adds Bob as a contact
5. Alice selects "Encrypt message", chooses Bob, types her message
6. Alice copies the encrypted output and sends it to Bob (via any channel)
7. Bob selects "Decrypt message" and pastes the encrypted text
8. Bob enters his password and reads Alice's message

## Development

Build in release mode (optimized for size):

```bash
cargo build --release
```

Run in development mode:

```bash
cargo run
```

## Security Considerations

- Always verify fingerprints out-of-band before trusting a contact's key
- Use a strong, unique password to protect your private key
- Back up your keys if needed, but store them securely
- The encrypted messages are only as secure as the recipient's key management
- This tool does not authenticate senders - implement your own verification workflow
