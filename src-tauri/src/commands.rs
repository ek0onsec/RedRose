use std::path::Path;
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tauri_plugin_dialog::DialogExt;

#[derive(Serialize)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub ext: String,
}

#[derive(Serialize, Clone)]
pub struct ProgressPayload {
    pub percent: u8,
    pub phase: String,
}

#[derive(Serialize)]
pub struct OperationResult {
    pub success: bool,
    pub saved_path: Option<String>,
    pub error: Option<String>,
}

fn emit_progress(app: &AppHandle, percent: u8, phase: &str) {
    let _ = app.emit("rr-progress", ProgressPayload {
        percent,
        phase: phase.to_string(),
    });
}

#[tauri::command]
pub fn get_file_info(path: String) -> Result<FileInfo, String> {
    let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
    let p = Path::new(&path);
    let name = p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&path)
        .to_string();
    let ext = p.extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", e))
        .unwrap_or_default();
    Ok(FileInfo { name, size: meta.len(), ext })
}

#[tauri::command]
pub async fn encrypt_file(
    app: AppHandle,
    file_path: String,
    password: String,
) -> Result<OperationResult, String> {
    let ext = Path::new(&file_path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", e))
        .unwrap_or_default();

    let suggested_name = format!(
        "{}.rr",
        Path::new(&file_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("file")
    );

    emit_progress(&app, 5, "Reading file...");
    let data = std::fs::read(&file_path).map_err(|e| e.to_string())?;

    emit_progress(&app, 15, "Deriving key + encrypting (Argon2id + XChaCha20)...");
    let encrypted = tokio::task::spawn_blocking(move || {
        redrose_core::encrypt(&data, &password, &ext)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    emit_progress(&app, 92, "Choose save location...");
    let save_result = app
        .dialog()
        .file()
        .set_file_name(&suggested_name)
        .add_filter("RedRose Encrypted", &["rr"])
        .blocking_save_file();

    match save_result {
        Some(path) => {
            let path_str = path.to_string();
            std::fs::write(&path_str, &encrypted).map_err(|e| e.to_string())?;
            emit_progress(&app, 100, "Done.");
            Ok(OperationResult {
                success: true,
                saved_path: Some(path_str),
                error: None,
            })
        }
        None => {
            emit_progress(&app, 0, "Cancelled.");
            Ok(OperationResult {
                success: false,
                saved_path: None,
                error: Some("Cancelled".to_string()),
            })
        }
    }
}

#[tauri::command]
pub async fn decrypt_file(
    app: AppHandle,
    file_path: String,
    password: String,
) -> Result<OperationResult, String> {
    let suggested_stem = Path::new(&file_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("decrypted")
        .to_string();

    emit_progress(&app, 5, "Reading file...");
    let data = std::fs::read(&file_path).map_err(|e| e.to_string())?;

    emit_progress(&app, 15, "Deriving key + decrypting (Argon2id + XChaCha20)...");
    let result = tokio::task::spawn_blocking(move || {
        redrose_core::decrypt(&data, &password)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    let (plaintext, original_ext) = result;

    emit_progress(&app, 92, "Choose save location...");
    let suggested_name = format!("{}{}", suggested_stem, original_ext);
    let save_result = app
        .dialog()
        .file()
        .set_file_name(&suggested_name)
        .blocking_save_file();

    match save_result {
        Some(path) => {
            let path_str = path.to_string();
            std::fs::write(&path_str, &plaintext).map_err(|e| e.to_string())?;
            emit_progress(&app, 100, "Done.");
            Ok(OperationResult {
                success: true,
                saved_path: Some(path_str),
                error: None,
            })
        }
        None => {
            emit_progress(&app, 0, "Cancelled.");
            Ok(OperationResult {
                success: false,
                saved_path: None,
                error: Some("Cancelled".to_string()),
            })
        }
    }
}
