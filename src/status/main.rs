use rust_mc_status::{McClient, ServerEdition, ServerInfo, ServerData};
use sqlx::sqlite::SqlitePoolOptions;
use std::time::Duration;
use tokio::time;
use serde_json::Value;
use sqlx::Pool;
use sqlx::Sqlite;

fn opt_str(s: Option<String>) -> String {
    s.unwrap_or_else(|| "N/A".to_string())
}

fn json_or_na<T: serde::Serialize>(opt: Option<T>) -> String {
    match opt {
        Some(v) => serde_json::to_string(&v).unwrap_or_else(|_| "N/A".into()),
        None => "N/A".into(),
    }
}

fn raw_to_string(v: Value) -> String {
    serde_json::to_string(&v).unwrap_or_else(|_| "N/A".into())
}

fn string_or_na(s: String) -> String {
    if s.trim().is_empty() { "N/A".into() } else { s }
}

async fn get_ips(pool: &Pool<Sqlite>) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query!("SELECT ip FROM ips")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|r| r.ip).collect())
}

async fn remove_ip(pool: &Pool<Sqlite>, ip: &str) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM ips WHERE ip = ?", ip)
        .execute(pool)
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("./server.db")
        .await?;

    println!("[INFO] Connected to database.");

    sqlx::migrate!("./migrations").run(&pool).await?;
    println!("[INFO] Database migrations complete.");

    let client = McClient::new()
        .with_timeout(Duration::from_secs(5))
        .with_max_parallel(10);

    println!("[INFO] Minecraft client initialized.");

    loop {
        println!("--- New loop iteration ---");
        let ips = match get_ips(&pool).await {
            Ok(ips) => {
                println!("[INFO] Loaded {} IP(s) from database.", ips.len());
                ips
            }
            Err(e) => {
                println!("[ERROR] Failed to get IPs: {}", e);
                vec![]
            }
        };

        if ips.is_empty() {
            println!("[INFO] No IPs to process. Sleeping...");
            time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        let servers: Vec<ServerInfo> = ips
            .iter()
            .map(|address| {
                println!("[INFO] Preparing server: {}", address);
                ServerInfo {
                    address: address.clone(),
                    edition: if address.contains(':') {
                        ServerEdition::Bedrock
                    } else {
                        ServerEdition::Java
                    },
                }
            })
            .collect();

        println!("[INFO] Pinging {} server(s)...", servers.len());
        let results = client.ping_many(&servers).await;

        for (server, result) in results {
            println!("[INFO] Processing server: {}", server.address);

            if let Ok(status) = result {
                println!("[SUCCESS] Got status for {}", server.address);

                let hostname = opt_str(Some(status.hostname.clone()));
                println!("[DATA] Hostname: {}", hostname);

                if let ServerData::Java(java) = status.data {
                    let version_name = opt_str(Some(java.version.name.clone()));
                    let version_protocol = java.version.protocol as i64;

                    println!(
                        "[DATA] Version: {} (protocol {})",
                        version_name, version_protocol
                    );

                    let players_online = java.players.online as i64;
                    let players_max = java.players.max as i64;
                    println!(
                        "[DATA] Players: {}/{}",
                        players_online, players_max
                    );

                    let description = opt_str(Some(java.description.clone()));
                    let gamemode = opt_str(java.gamemode.clone());
                    let software = opt_str(java.software.clone());
                    let plugins = json_or_na(java.plugins.clone());
                    let mods = json_or_na(java.mods.clone());
                    let favicon = opt_str(java.favicon.clone());
                    let raw_data = raw_to_string(java.raw_data.clone());

                    println!(
                        "[DATA] Description: {}\n[DATA] Gamemode: {}\n[DATA] Software: {}\n[DATA] Plugins: {}\n[DATA] Mods: {}",
                        description, gamemode, software, plugins, mods
                    );

                    sqlx::query!(
                        r#"
                        INSERT INTO servers (
                            address, hostname, version_name, version_protocol,
                            players_online, players_max, description, gamemode,
                            software, plugins, mods, favicon, raw_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        "#,
                        server.address,
                        hostname,
                        version_name,
                        version_protocol,
                        players_online,
                        players_max,
                        description,
                        gamemode,
                        software,
                        plugins,
                        mods,
                        favicon,
                        raw_data,
                    )
                    .execute(&pool)
                    .await?;

                    println!("[INFO] Inserted server {} into DB", server.address);

                    if let Some(sample) = java.players.sample {
                        println!("[INFO] Found {} player(s) online:", sample.len());
                        for player in sample {
                            let player_name = string_or_na(player.name.clone());
                            let player_uuid = player.id.clone();
                            println!("[PLAYER] {} ({})", player_name, player_uuid);
                            scanerr::add_player(&pool, &player_name, &player_uuid, &server.address).await?;
                        }
                    } else {
                        println!("[INFO] No player sample data.");
                    }
                }
            } else {
                println!("[WARN] Failed to get status for {}: {:?}", server.address, result.err());
            }

            remove_ip(&pool, &server.address).await?;
            println!("[INFO] Removed IP {} from queue.", server.address);
        }

        println!("[INFO] Loop complete. Sleeping for 1 second.\n");
        time::sleep(Duration::from_secs(1)).await;
    }
}
