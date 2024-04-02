use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind},
    path::Path,
    thread::sleep,
    time::Duration,
};

use clipboard_win::get_clipboard_string;
use reqwest::blocking::get;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use std::io::Write;
use std::os::windows::process::CommandExt;
use winapi::um::winbase::CREATE_NO_WINDOW;

#[derive(Serialize, Deserialize)]
struct Config {
    download_directory: String,
    file_types: Vec<String>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let is_secondary_instance = args.len() > 1 && args[1] == "secondary";
    let config = get_config().unwrap_or(create_config_if_not_exists().unwrap());

    if !is_secondary_instance {
        // main terminal (popup window)
        std::process::Command::new("clipboard_to_file.exe")
            .arg("secondary")
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap();

        // exit main terminal since secondary is open
        std::process::exit(0);
    }

    println!("\n\nWatching clipboard...\n\n");

    loop {
        match download_clipboard_file(&config) {
            Ok(_) => { /*Do nothing */ }
            Err(e) => eprintln!("Failed to download file: {}", e),
        }

        sleep(Duration::from_secs(5));
    }
}

fn download_clipboard_file(config: &Config) -> Result<(), std::io::Error> {
    match get_clipboard_string() {
        Ok(s) => {
            if s.starts_with("https://") || s.starts_with("https://") {
                let response = get(&s).expect("Failed to send request");
                if response.status().is_success() {
                    //println!("{}", response.status());
                    let file_name = Path::new(&s).file_name().unwrap();
                    let user_download_directory = &config.download_directory;
                    let final_download_directory = format!(
                        "{}\\{}",
                        user_download_directory,
                        file_name.to_str().unwrap().to_string()
                    );
                    if Path::new(&final_download_directory).exists() {
                        return Err(Error::new(ErrorKind::AlreadyExists, "File already exists"));
                    }
                    let mut dest =
                        File::create(final_download_directory).expect("Failed to create file");
                    let bytes = response.bytes().expect("Failed to read response bytes");
                    dest.write_all(&bytes).expect("Failed to write content");
                    println!(
                        "\nDownloaded {:#?} to {}\n",
                        file_name, user_download_directory
                    );
                } else {
                    println!("\nFailed to download file: {}\n", response.status());
                }
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "URL must start with http:// or https://",
                ));
            }
        }
        Err(e) => eprintln!("{}", e),
    }
    Ok(())
}

fn config_prompt_helper_file_types() -> Vec<String> {
    // define inputs here
    let mut file_types_input_vec: Vec<String> = Vec::new();

    // prompt for file_types_p
    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        input = input.to_lowercase().trim().to_string();
        if input.to_lowercase() == "done" {
            break;
        } else if input.to_lowercase().contains(".") {
            file_types_input_vec.push(input.replace(".", "").trim().to_string());
        } else {
            file_types_input_vec.push(input);
        }
    }
    file_types_input_vec
}

fn config_prompt_helper_download_directory() -> String {
    // define inputs here
    let mut download_dir_input = String::new();

    // prompt for download_directory_p
    println!("\n\nExample Download Directory: C:\\Users\\ExampleUser\\Desktop");
    println!("\n Enter a downloads directory: ");
    io::stdin().read_line(&mut download_dir_input).unwrap();
    download_dir_input = download_dir_input.trim_end().to_string();

    if !download_dir_input.is_empty() && Path::new(&download_dir_input).exists() {
        return download_dir_input;
    } else {
        return config_prompt_helper_download_directory();
    }
}

fn prompt_user_for_config_values() -> Config {
    let download_directory: String = config_prompt_helper_download_directory();
    let file_types: Vec<String> = config_prompt_helper_file_types();

    Config {
        download_directory,
        file_types,
    }
}

fn get_config() -> Option<Config> {
    let config_path = "./config.json".to_string();
    let config_file_exists = Path::new(&config_path).exists();
    if config_file_exists {
        let config_file_string = fs::read_to_string(config_path).unwrap();
        let config = from_str(&config_file_string).unwrap();
        config
    } else {
        None
    }
}

fn create_config_if_not_exists() -> Result<Config, Box<dyn std::error::Error>> {
    let config_path = "./config.json".to_string();
    let config_file_exists = Path::new(&config_path).exists();
    let config_file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .open(config_path);
    match config_file {
        Ok(mut config_file) => {
            if !config_file_exists {
                let config_struct = prompt_user_for_config_values();
                let config_json_string = serde_json::to_string_pretty(&config_struct)?;
                config_file
                    .write_all(config_json_string.as_bytes())
                    .expect("Failed to write_all to config.json");
                return Ok(config_struct);
            } else {
                return Ok(get_config().unwrap());
            }
        }
        Err(e) => {
            eprintln!("Config File Error: {}", e.to_string());
            return Err(Box::new(e));
        }
    }
}
