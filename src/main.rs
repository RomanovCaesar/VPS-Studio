#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod backend;
mod config;
mod models;
mod vault;

use backend::{
    check_watched_files, chmod_remote, collect_metrics, create_remote_folder, delete_remote, generate_ssh_key,
    list_remote_dir, open_remote_file, read_clipboard_text, read_shell, rename_remote, resize_shell, run_command,
    start_local_shell, start_shell, stop_shell, test_connection, upload_edited_file,
    write_clipboard_text, write_shell, ShellStore,
};
use config::{load_hosts, save_hosts, vault_status, load_known_hosts, save_known_hosts, import_known_hosts, add_known_host};

fn main() {
    // Old downloads and leftover temporary keys; not needed to start the UI.
    std::thread::spawn(backend::cleanup_temp_files);
    tauri::Builder::default()
        .manage(ShellStore::default())
        .invoke_handler(tauri::generate_handler![
            load_hosts,
            save_hosts,
            load_known_hosts,
            save_known_hosts,
            import_known_hosts,
            add_known_host,
            test_connection,
            generate_ssh_key,
            start_shell,
            read_shell,
            write_shell,
            stop_shell,
            run_command,
            collect_metrics,
            list_remote_dir,
            open_remote_file,
            start_local_shell,
            upload_edited_file,
            check_watched_files,
            create_remote_folder,
            delete_remote,
            read_clipboard_text,
            write_clipboard_text,
            rename_remote,
            chmod_remote,
            resize_shell,
            vault_status,
            vault::vault_get,
            vault::vault_set
        ])
        .run(tauri::generate_context!())
        .expect("error while running VPS Studio");
}
