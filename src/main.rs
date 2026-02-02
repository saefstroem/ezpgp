mod contacts;
mod crypto;
mod error;
mod ui;

use contacts::ContactBook;
use crypto::KeyPair;
use error::{Error, Result};
use sequoia_openpgp::{parse::Parse, Cert};
use std::{fs, path::PathBuf};
use zeroize::{Zeroize, Zeroizing};

struct Paths {
    private_key: PathBuf,
    public_key: PathBuf,
    db: PathBuf,
}

impl Paths {
    fn new() -> Result<Self> {
        let home = dirs::home_dir().ok_or(Error::HomeNotFound)?;
        let dir = home.join(".ezpgp");
        fs::create_dir_all(&dir)?;
        Ok(Self {
            private_key: dir.join("private.asc"),
            public_key: dir.join("public.asc"),
            db: dir.join("contacts.db"),
        })
    }
}

fn main() -> Result<()> {
    let paths = Paths::new()?;
    let contacts = ContactBook::open(&paths.db)?;

    // Initialize keys
    let keypair = if paths.private_key.exists() {
        let password = ui::get_password("Enter your password: ")?;
        let cert = crypto::load(&paths.private_key, &password)?;
        KeyPair { cert, password }
    } else {
        ui::print_color("First time setup\n\n", crossterm::style::Color::Green)?;
        ui::print_color("Do you want to:\n", crossterm::style::Color::Cyan)?;
        println!("1. Create new keys");
        println!("2. Import existing private key\n");

        let choice = ui::get_input("Select option (1 or 2): ")?;

        match choice.trim() {
            "1" => {
                // Generate new keys
                ui::print_color("Creating your keys...\n", crossterm::style::Color::Green)?;
                let password = ui::get_new_password()?;
                let cert = crypto::generate()?;
                crypto::save(&cert, &password, &paths.private_key, &paths.public_key)?;
                ui::print_color("Keys created successfully!\n", crossterm::style::Color::Green)?;
                KeyPair { cert, password }
            }
            "2" => {
                // Import existing key
                ui::print_color("Importing existing private key...\n", crossterm::style::Color::Green)?;
                let private_key = ui::get_multiline_input("Paste your private key (press Ctrl+D when done):\n")?;
                let password = ui::get_password("Enter the password for this key: ")?;

                let cert = crypto::import_private_key(&private_key, &password)?;
                crypto::save(&cert, &password, &paths.private_key, &paths.public_key)?;
                ui::print_color("Private key imported successfully!\n", crossterm::style::Color::Green)?;
                KeyPair { cert, password }
            }
            _ => {
                ui::print_color("Invalid option, creating new keys...\n", crossterm::style::Color::Yellow)?;
                let password = ui::get_new_password()?;
                let cert = crypto::generate()?;
                crypto::save(&cert, &password, &paths.private_key, &paths.public_key)?;
                ui::print_color("Keys created successfully!\n", crossterm::style::Color::Green)?;
                KeyPair { cert, password }
            }
        }
    };

    ui::print_color(
        &format!("Your fingerprint: {}\n\n", keypair.fingerprint()),
        crossterm::style::Color::Cyan,
    )?;

    loop {
        ui::clear_screen()?;
        ui::print_menu()?;

        let choice = ui::get_input("Select option: ")?;
        let mut password_copy = keypair.password.clone();

        let result = match choice.trim() {
            "1" => encrypt_message_flow(&contacts, &keypair.cert),
            "2" => decrypt_message_flow(&keypair.cert, &mut password_copy),
            "3" => add_contact_flow(&contacts),
            "4" => remove_contact_flow(&contacts),
            "5" => list_contacts_flow(&contacts),
            "6" => view_public_key_flow(&paths),
            "7" => {
                if reset_flow()? {
                    break;
                }
                Ok(())
            }
            "8" => break,
            _ => {
                ui::print_color("Invalid option\n", crossterm::style::Color::Red)?;
                Ok(())
            }
        };

        password_copy.zeroize();

        if let Err(e) = result {
            ui::print_color(&format!("Error: {}\n", e), crossterm::style::Color::Red)?;
        }

        ui::pause()?;
    }

    Ok(())
}

fn encrypt_message_flow(contacts: &ContactBook, _cert: &Cert) -> Result<()> {
    ui::clear_screen()?;
    ui::print_color("Encrypt Message\n\n", crossterm::style::Color::Green)?;

    let contact_list = contacts.list()?;
    if contact_list.is_empty() {
        ui::print_color("No contacts found. Add a contact first.\n", crossterm::style::Color::Red)?;
        return Ok(());
    }

    println!("Select recipient:");
    let idx = ui::select_from_list(&contact_list, |c| c.name.clone())?;
    let contact = &contact_list[idx];

    let recipient_cert = Cert::from_bytes(contact.public_key.as_bytes())?;

    let message = ui::get_multiline_input("\nEnter your message (press Ctrl+D when done):\n")?;
    let encrypted = crypto::encrypt(message.as_bytes(), &recipient_cert)?;

    ui::clear_screen()?;
    ui::print_color(
        &format!("Message encrypted for {}:\n\n", contact.name),
        crossterm::style::Color::Green,
    )?;
    ui::print_color("━━━━━━━━━━ ENCRYPTED MESSAGE ━━━━━━━━━━\n", crossterm::style::Color::Yellow)?;
    println!("{}", encrypted);
    ui::print_color("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", crossterm::style::Color::Yellow)?;

    Ok(())
}

fn decrypt_message_flow(cert: &Cert, password: &mut Zeroizing<String>) -> Result<()> {
    ui::clear_screen()?;
    ui::print_color("Decrypt Message\n\n", crossterm::style::Color::Green)?;

    let encrypted = ui::get_multiline_input("Paste encrypted message (press Ctrl+D when done):\n")?;
    let decrypted = crypto::decrypt(&encrypted, cert, password)?;

    ui::clear_screen()?;
    ui::print_color("Decrypted message:\n\n", crossterm::style::Color::Green)?;
    ui::print_color("━━━━━━━━━━ DECRYPTED MESSAGE ━━━━━━━━━━\n", crossterm::style::Color::Yellow)?;
    println!("{}", String::from_utf8_lossy(&decrypted));
    ui::print_color("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", crossterm::style::Color::Yellow)?;

    Ok(())
}

fn add_contact_flow(contacts: &ContactBook) -> Result<()> {
    ui::clear_screen()?;
    ui::print_color("Add Contact\n\n", crossterm::style::Color::Green)?;

    let name = ui::get_input("Contact name: ")?;
    let pubkey = ui::get_multiline_input("Paste their public key (press Ctrl+D when done):\n")?;

    contacts.add(name.trim(), pubkey.trim())?;
    ui::print_color("Contact added successfully!\n", crossterm::style::Color::Green)?;

    Ok(())
}

fn remove_contact_flow(contacts: &ContactBook) -> Result<()> {
    ui::clear_screen()?;
    ui::print_color("Remove Contact\n\n", crossterm::style::Color::Green)?;

    let contact_list = contacts.list()?;
    if contact_list.is_empty() {
        ui::print_color("No contacts found.\n", crossterm::style::Color::Red)?;
        return Ok(());
    }

    let idx = ui::select_from_list(&contact_list, |c| c.name.clone())?;
    let contact = &contact_list[idx];

    contacts.remove(&contact.name)?;
    ui::print_color(&format!("Removed {}\n", contact.name), crossterm::style::Color::Green)?;

    Ok(())
}

fn list_contacts_flow(contacts: &ContactBook) -> Result<()> {
    ui::clear_screen()?;
    ui::print_color("Contacts\n\n", crossterm::style::Color::Green)?;

    let contact_list = contacts.list()?;
    if contact_list.is_empty() {
        ui::print_color("No contacts found.\n", crossterm::style::Color::Yellow)?;
    } else {
        for contact in contact_list {
            let cert = Cert::from_bytes(contact.public_key.as_bytes())?;
            println!("• {} ({})", contact.name, cert.fingerprint());
        }
    }

    Ok(())
}

fn view_public_key_flow(paths: &Paths) -> Result<()> {
    ui::clear_screen()?;
    ui::print_color("Your Public Key\n\n", crossterm::style::Color::Green)?;

    let public_key = fs::read_to_string(&paths.public_key)?;

    ui::print_color("━━━━━━━━━━ PUBLIC KEY ━━━━━━━━━━\n", crossterm::style::Color::Yellow)?;
    println!("{}", public_key);
    ui::print_color("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", crossterm::style::Color::Yellow)?;

    ui::print_color("\nShare this public key with others so they can send you encrypted messages.\n", crossterm::style::Color::Cyan)?;
    ui::print_color("   You can also find it at: ", crossterm::style::Color::DarkGrey)?;
    println!("{}", paths.public_key.display());

    Ok(())
}

fn reset_flow() -> Result<bool> {
    ui::clear_screen()?;
    ui::print_color("WARNING: RESET EZPGP\n\n", crossterm::style::Color::Red)?;
    ui::print_color("This will DELETE:\n", crossterm::style::Color::Yellow)?;
    println!("• Your private key");
    println!("• Your public key");
    println!("• All contacts\n");
    ui::print_color("This action CANNOT be undone!\n\n", crossterm::style::Color::Red)?;

    if ui::confirm_action("Type 'DELETE' to confirm: ", "DELETE")? {
        let paths = Paths::new()?;
        let _ = fs::remove_file(&paths.private_key);
        let _ = fs::remove_file(&paths.public_key);
        let _ = fs::remove_file(&paths.db);
        ui::print_color("ezpgp has been reset.\n", crossterm::style::Color::Green)?;
        return Ok(true);
    }

    Ok(false)
}
