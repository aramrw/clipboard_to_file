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
    debugger: bool,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let is_secondary_instance = args.len() > 1 && args[1] == "secondary";
    let config = get_config().unwrap_or(create_config_if_not_exists().unwrap());
    let mut previous_clipboard_text: String = "".to_string();
    // if it reaches here the user has created a config / one exists
    if !is_secondary_instance && !config.debugger {
        // main terminal (popup window)
        std::process::Command::new("clipboard_to_file.exe")
            .arg("secondary")
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap();

        // exit main terminal since secondary is open
        std::process::exit(0);
    }

    loop {
        match download_clipboard_file(&config, &previous_clipboard_text) {
            Ok(current) => {
                if previous_clipboard_text != "" && previous_clipboard_text != current {
                    //println!("\n{} != {}\n", previous_clipboard_text, current);
                    std::fs::remove_file(previous_clipboard_text).unwrap();
                    previous_clipboard_text = current
                } else {
                    // stitch the path together
                    previous_clipboard_text = current
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    eprintln!("\nFailed to download file: {}", e);
                } else {
                    println!("\nFailed to download file: {}", e);
                }
            }
        }

        sleep(Duration::from_secs(1));
    }
}

fn download_clipboard_file(
    config: &Config,
    _previous_clipboard_text: &str,
) -> Result<String, std::io::Error> {
    match get_clipboard_string() {
        Ok(s) => {
            if s.starts_with("https://") || s.starts_with("https://") {
                let response = get(&s).expect("Failed to send request");
                if response.status().is_success() {
                    //println!("{}", response.status());
                    let file_name = Path::new(&s)
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string();

                    // check if the file contains config file types
                    if config
                        .file_types
                        .iter()
                        .all(|f_type| !file_name.contains(f_type))
                    {
                        eprintln!(
                            "\n{:#?} does not contain any of the file types; ",
                            file_name
                        );
                        eprintln!("\nTo download files of this type, add the extension to your config.json; ");
                        return Ok(s);
                    }
                    let user_download_directory = &config.download_directory;
                    let final_download_directory =
                        format!("{}\\{}", user_download_directory, file_name,);
                    if Path::new(&final_download_directory).exists() {
                        return Err(Error::new(ErrorKind::AlreadyExists, "File already exists"));
                        //return Ok(s);
                    }
                    let mut dest =
                        File::create(final_download_directory).expect("Failed to create file");
                    let bytes = response.bytes().expect("Failed to read response bytes");
                    dest.write_all(&bytes).expect("Failed to write content");
                    println!(
                        "\nDownloaded {:#?} to {}\n",
                        file_name, user_download_directory
                    );
                    // if no errors, return the clipboard back to the caller
                    let return_file_name = format!("{}\\{}", user_download_directory, file_name);
                    return Ok(return_file_name);
                } else {
                    eprintln!("\nFailed to download file: {}", response.status());
                    Ok(s)
                }
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "\nURL must start with http:// or https://",
                ));
            }
        }
        Err(e) => {
            eprintln!("{}", e);
            return Ok("".to_string());
        }
    }
}

fn config_prompt_helper_file_types() -> Vec<String> {
    // define inputs here
    let mut file_types_input_vec: Vec<String> = Vec::new();
    println!("\nFile type examples: `mp3` `jpg` `png` `svg`");
    println!("Enter `Done` once finished");
    println!("Or Enter `Default` for `mp3` && `jpg`");

    println!("\nEnter File Types: ");

    // prompt for file_types_p
    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        input = input.to_lowercase().trim().to_string();
        if input.contains("done") {
            break;
        } else if input.contains(".") {
            file_types_input_vec.push(input.replace(".", "").trim().to_string());
        } else if input.contains("default") {
            file_types_input_vec = vec!["mp3".to_string(), "jpg".to_string()];
            return file_types_input_vec;
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
    println!("Example Download Directory: C:\\Users\\ExampleUser\\Desktop");
    println!("\nEnter a Downloads Directory: ");
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
        debugger: false,
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
