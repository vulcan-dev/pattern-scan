use std::io::Read;
use winapi::um::winreg::HKEY_LOCAL_MACHINE;
use winreg::{RegKey};

pub fn find(name: &str) -> String {
    use std::path::PathBuf;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let steam_key = match hklm.open_subkey("SOFTWARE\\WOW6432Node\\Valve\\Steam") {
        Ok(key) => key,
        Err(_) => panic!("could not open steam key, is steam installed? if so, make sure you're on 64-bit windows"),
    };

    let install_path: String = steam_key.get_value("InstallPath").unwrap();

    let mut path: PathBuf = PathBuf::from(install_path);
    let mut game_path = path.clone();
    game_path.push("steamapps\\common\\");
    game_path.push(name);

    if game_path.exists() {
        return game_path.to_str().unwrap().to_string();
    }

    path.push("steamapps\\libraryfolders.vdf");
    if path.exists() {
        let mut file = std::fs::File::open(path).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let mut lines = contents.lines();

        while let Some(line) = lines.next() {
            let line = line.replace("\t", "");

            // look for "path"
            if line.starts_with("\"path\"") {
                let line = line.replace("\"path\"", "");
                let path = line.replace("\"", "");

                // check if the path exists
                let mut game_path = PathBuf::from(path);
                game_path.push("steamapps\\common\\");
                game_path.push(name);
                if game_path.exists() {
                    return game_path.to_str().unwrap().to_string();
                }
            }
        }
    } else {
        error!("Could not find libraryfolders.vdf");
    }

    String::new()
}