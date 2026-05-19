use colored::Colorize;

pub fn log_ok(msg: &str) {
    println!("{} {}", "[+]".green(), msg);
}

pub fn log_info(msg: &str) {
    println!("{} {}", "[*]".cyan(), msg);
}

pub fn log_error(msg: &str) {
    println!("{} {}", "[-]".red(), msg);
}

pub fn log_warn(msg: &str) {
    println!("\x1b[33m[!] {}\x1b[0m", msg);
}