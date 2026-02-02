mod error;

pub use error::{CryptoError, Result};

use sequoia_openpgp::{
    cert::CertBuilder,
    crypto::Password,
    parse::{stream::*, Parse},
    policy::StandardPolicy,
    serialize::{stream::*, Marshal},
    Cert, Fingerprint,
};
use std::{
    fs,
    io::{self, Write as _},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

pub struct KeyPair {
    pub cert: Cert,
    pub password: Zeroizing<String>,
}

impl KeyPair {
    pub fn fingerprint(&self) -> Fingerprint {
        self.cert.fingerprint()
    }
}

pub fn generate() -> Result<Cert> {
    let (cert, _) = CertBuilder::new()
        .add_userid("ezpgp user")
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .generate()?;
    Ok(cert)
}

pub fn save(cert: &Cert, password: &Zeroizing<String>, private_path: &Path, public_path: &Path) -> Result<()> {
    // Save encrypted private key
    let mut private_key = Vec::new();
    {
        let message = Message::new(&mut private_key);
        let message = Armorer::new(message).build()?;
        let message = Encryptor2::with_passwords(
            message,
            vec![Password::from(password.as_str())],
        ).build()?;
        let mut literal_writer = LiteralWriter::new(message).build()?;
        cert.as_tsk().serialize(&mut literal_writer)?;
        literal_writer.finalize()?;
    }
    fs::write(private_path, &private_key)?;
    private_key.zeroize();

    // Save public key
    let mut public_key = Vec::new();
    cert.armored().serialize(&mut public_key)?;
    fs::write(public_path, &public_key)?;

    Ok(())
}

pub fn load(path: &Path, password: &Zeroizing<String>) -> Result<Cert> {
    let encrypted_bytes = fs::read(path)?;

    // Decrypt the encrypted private key
    let policy = StandardPolicy::new();

    // Parse the encrypted message
    let helper = LoadHelper {
        password: Password::from(password.as_str()),
    };

    let mut decryptor = DecryptorBuilder::from_bytes(&encrypted_bytes)?
        .with_policy(&policy, None, helper)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let mut decrypted = Vec::new();
    io::copy(&mut decryptor, &mut decrypted)?;

    // Parse the decrypted certificate
    Cert::from_bytes(&decrypted).map_err(|_| CryptoError::InvalidCert)
}

struct LoadHelper {
    password: Password,
}

impl DecryptionHelper for LoadHelper {
    fn decrypt<D>(
        &mut self,
        _pkesks: &[sequoia_openpgp::packet::PKESK],
        skesks: &[sequoia_openpgp::packet::SKESK],
        _sym_algo: Option<sequoia_openpgp::types::SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> sequoia_openpgp::Result<Option<Fingerprint>>
    where
        D: FnMut(sequoia_openpgp::types::SymmetricAlgorithm, &sequoia_openpgp::crypto::SessionKey) -> bool,
    {
        for skesk in skesks {
            if let Ok((algo, session_key)) = skesk.decrypt(&self.password) {
                if decrypt(algo, &session_key) {
                    return Ok(None);
                }
            }
        }
        Err(anyhow::anyhow!("Wrong password or decryption failed"))
    }
}

impl VerificationHelper for LoadHelper {
    fn get_certs(&mut self, _ids: &[sequoia_openpgp::KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(vec![])
    }

    fn check(&mut self, _structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        Ok(())
    }
}

pub fn import_private_key(private_key_data: &str, _password: &Zeroizing<String>) -> Result<Cert> {
    // Parse the certificate from the armored private key
    let cert = Cert::from_bytes(private_key_data.as_bytes())
        .map_err(|_| CryptoError::InvalidCert)?;

    // Verify it's a secret key by trying to access secret keys
    let policy = StandardPolicy::new();
    cert.keys()
        .unencrypted_secret()
        .with_policy(&policy, None)
        .for_transport_encryption()
        .next()
        .ok_or(CryptoError::InvalidCert)?;

    Ok(cert)
}

pub fn encrypt(plaintext: &[u8], recipient_cert: &Cert) -> Result<String> {
    let policy = StandardPolicy::new();
    let mut encrypted = Vec::new();
    {
        let message_writer = Message::new(&mut encrypted);
        let message_writer = Armorer::new(message_writer).build()?;
        let recipients = recipient_cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .for_transport_encryption();

        let message_writer = Encryptor2::for_recipients(message_writer, recipients)
            .build()
            .map_err(|_| CryptoError::NoSuitableKey)?;

        let mut literal_writer = LiteralWriter::new(message_writer)
            .build()
            ?;

        literal_writer.write_all(plaintext)?;
        literal_writer.finalize()?;
    }

    Ok(String::from_utf8_lossy(&encrypted).to_string())
}

pub fn decrypt(ciphertext: &str, cert: &Cert, password: &Zeroizing<String>) -> Result<Zeroizing<Vec<u8>>> {
    let policy = StandardPolicy::new();
    let helper = DecryptHelper {
        cert,
        password: Password::from(password.as_str()),
    };

    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext.as_bytes())
        ?
        .with_policy(&policy, None, helper)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let mut decrypted = Zeroizing::new(Vec::new());
    io::copy(&mut decryptor, &mut *decrypted)?;

    Ok(decrypted)
}

struct DecryptHelper<'a> {
    cert: &'a Cert,
    password: Password,
}

impl<'a> DecryptionHelper for DecryptHelper<'a> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[sequoia_openpgp::packet::PKESK],
        _skesks: &[sequoia_openpgp::packet::SKESK],
        sym_algo: Option<sequoia_openpgp::types::SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> sequoia_openpgp::Result<Option<Fingerprint>>
    where
        D: FnMut(sequoia_openpgp::types::SymmetricAlgorithm, &sequoia_openpgp::crypto::SessionKey) -> bool,
    {
        let policy = StandardPolicy::new();

        eprintln!("DEBUG: Total PKESKs: {}", pkesks.len());
        eprintln!("DEBUG: Total secret keys: {}", self.cert.keys().secret().count());
        eprintln!("DEBUG: Unencrypted secret keys: {}", self.cert.keys().unencrypted_secret().count());

        for (i, pkesk) in pkesks.iter().enumerate() {
            eprintln!("DEBUG: Trying PKESK {}", i);

            // Try to find a suitable secret key (encrypted or unencrypted)
            let key = self
                .cert
                .keys()
                .secret()
                .with_policy(&policy, None)
                .for_transport_encryption()
                .next()
                .ok_or_else(|| sequoia_openpgp::Error::InvalidOperation("No suitable key".into()))?;

            eprintln!("DEBUG: Found key, has_secret: {}", key.key().has_secret());

            // Check if the key is already unencrypted or needs decryption
            let secret = key.key().clone().parts_into_secret()?;
            let decrypted = if secret.secret().is_encrypted() {
                eprintln!("DEBUG: Key is encrypted, decrypting...");
                secret.decrypt_secret(&self.password)?
            } else {
                eprintln!("DEBUG: Key is already unencrypted");
                secret
            };

            let mut keypair = decrypted.into_keypair()?;

            eprintln!("DEBUG: Created keypair");

            match pkesk.decrypt(&mut keypair, sym_algo) {
                Some((algo, session_key)) => {
                    eprintln!("DEBUG: PKESK decrypt succeeded with algo: {:?}", algo);
                    if decrypt(algo, &session_key) {
                        eprintln!("DEBUG: Session key worked!");
                        return Ok(None);
                    } else {
                        eprintln!("DEBUG: Session key didn't work");
                    }
                }
                None => {
                    eprintln!("DEBUG: PKESK decrypt returned None");
                }
            }
        }
        eprintln!("DEBUG: All PKESKs failed");
        Err(anyhow::anyhow!("Decryption failed"))
    }
}

impl<'a> VerificationHelper for DecryptHelper<'a> {
    /// We don't verify signatures, we only care about encryption
    fn get_certs(&mut self, _ids: &[sequoia_openpgp::KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(vec![])
    }

    /// Any format is accepted
    fn check(&mut self, _structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        Ok(())
    }
}
