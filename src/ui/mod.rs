mod error;

pub use error::{UiError, Result};

use crossterm::{
    cursor, execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{Clear, ClearType},
};
use std::io::{self, Write as _};
use zeroize::Zeroizing;

pub fn clear_screen() -> Result<()> {
    execute!(io::stdout(), Clear(ClearType::All), cursor::MoveTo(0, 0))?;
    Ok(())
}

pub fn print_color(text: &str, color: Color) -> Result<()> {
    execute!(
        io::stdout(),
        SetForegroundColor(color),
        Print(text),
        ResetColor
    )?;
    Ok(())
}

pub fn print_menu() -> Result<()> {
    print_color("╔══════════════════════════════╗\n", Color::Blue)?;
    print_color("║         ezpgp v0.1.0         ║\n", Color::Blue)?;
    print_color("╚══════════════════════════════╝\n\n", Color::Blue)?;
    println!("1. Encrypt message");
    println!("2. Decrypt message");
    println!("3. Add contact");
    println!("4. Remove contact");
    println!("5. List contacts");
    println!("6. View my public key");
    println!("7. Reset ezpgp");
    println!("8. Exit\n");
    Ok(())
}

pub fn get_input(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input)
}

pub fn get_multiline_input(prompt: &str) -> Result<Zeroizing<String>> {
    print_color(prompt, Color::Cyan)?;
    let mut input = Zeroizing::new(String::new());
    let mut line = String::new();
    while io::stdin().read_line(&mut line)? > 0 {
        input.push_str(&line);
        line.clear();
    }
    Ok(input)
}

pub fn get_password(prompt: &str) -> Result<Zeroizing<String>> {
    print!("{}", prompt);
    io::stdout().flush()?;
    Ok(Zeroizing::new(rpassword::read_password()?))
}

pub fn get_new_password() -> Result<Zeroizing<String>> {
    loop {
        let pass1 = get_password("Set your password: ")?;
        let pass2 = get_password("Confirm password: ")?;

        if pass1.as_str() == pass2.as_str() {
            return Ok(pass1);
        }
        print_color("❌ Passwords don't match. Try again.\n", Color::Red)?;
    }
}

pub fn pause() -> Result<()> {
    print_color("\nPress Enter to continue...", Color::DarkGrey)?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(())
}

pub fn select_from_list<T>(items: &[T], display: impl Fn(&T) -> String) -> Result<usize> {
    for (i, item) in items.iter().enumerate() {
        println!("{}. {}", i + 1, display(item));
    }

    let choice = get_input("\nSelect number: ")?;
    let idx: usize = choice
        .trim()
        .parse()
        .map_err(|_| UiError::Parse("Invalid number".to_string()))?;

    if idx == 0 || idx > items.len() {
        return Err(UiError::InvalidInput);
    }

    Ok(idx - 1)
}

pub fn confirm_action(prompt: &str, confirmation_word: &str) -> Result<bool> {
    let input = get_input(prompt)?;
    Ok(input.trim() == confirmation_word)
}
