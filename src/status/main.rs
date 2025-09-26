use rust_mc_status::{McClient, ServerEdition, ServerInfo, ServerData};
use sqlx::sqlite::SqlitePoolOptions;
use std::time::Duration;
use tokio::time;
use serde::Serialize;
use serde_json::Value;

fn opt_str(s: Option<String>) -> String {
    s.unwrap_or_else(|| "N/A".to_string())
}

fn json_or_na<T: Serialize>(opt: Option<T>) -> String {
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

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("./server.db")
        .await?;
    println!("Connected to SQLITE!");

    sqlx::migrate!("./migrations").run(&pool).await?;
    println!("Migrations completed!");

    let client = McClient::new()
        .with_timeout(Duration::from_secs(5))
        .with_max_parallel(10);

    loop {
        let ips = get_ips(&pool).await?;

        let servers: Vec<ServerInfo> = ips
            .into_iter()
            .map(|address| ServerInfo {
                address: address.clone(),
                edition: if address.contains(':') {
                    ServerEdition::Bedrock
                } else {
                    ServerEdition::Java
                },
            })
            .collect();

        let results = client.ping_many(&servers).await;

        for (server, result) in results {
            println!("Server: {} - {:?}", server.address, result);

            // clone the address early so we can use it multiple times
            let address = server.address.clone();

            if let Ok(status) = result {
                // hostname: Option<String>
                let hostname = opt_str(Some(status.hostname.clone()));

                // dns fields
                let dns_a_records = status
                    .dns
                    .as_ref()
                    .map(|d| serde_json::to_string(&d.a_records).unwrap_or_else(|_| "N/A".into()))
                    .unwrap_or_else(|| "N/A".into());
                let dns_cname = opt_str(status.dns.as_ref().and_then(|d| d.cname.clone()));

                if let ServerData::Java(java) = status.data {
                    // version_name may be Option<String>
                    let version_name = opt_str(Some(java.version.name.clone()));
                    let version_protocol = java.version.protocol as i64;

                    let players_online = java.players.online as i64;
                    let players_max = java.players.max as i64;

                    let description = opt_str(Some(java.description.clone()));
                    let gamemode = opt_str(java.gamemode.clone());
                    let software = opt_str(java.software.clone());

                    // plugins / mods may be Option<Vec<...>>
                    let plugins = json_or_na(java.plugins.clone());
                    let mods = json_or_na(java.mods.clone());

                    let favicon = opt_str(java.favicon.clone());
                    let raw_data = raw_to_string(java.raw_data.clone());

                    // Insert server row and get id
                    let server_id = sqlx::query!(
                        r#"
                        INSERT INTO servers (
                            address, hostname, dns_a_records, dns_cname,
                            version_name, version_protocol,
                            players_online, players_max,
                            description, gamemode, software, plugins, mods, favicon, raw_data
                        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
                        RETURNING id
                        "#,
                        address,
                        hostname,
                        dns_a_records,
                        dns_cname,
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
                    .fetch_one(&pool)
                    .await?
                    .id;

                    // handle sample players: java.players.sample is Option<Vec<Player>>
                    if let Some(sample) = java.players.sample {
                        for player in sample {
                            // `player.name` in your crate appears to be a plain String
                            let player_name = string_or_na(player.name.clone());
                            let player_uuid = player.id.clone();

                            // fetch existing ips JSON (Option<String>) - **borrow** the record with as_ref()
                            let existing = sqlx::query!(
                                r#"SELECT ips FROM players WHERE uuid = ?1"#,
                                player_uuid
                            )
                            .fetch_optional(&pool)
                            .await?;

                            // build ip list by borrowing existing with as_ref()
                            let mut ip_list: Vec<String> = existing
                                .as_ref()                                   // borrow, don't move
                                .and_then(|r| r.ips.as_deref())            // Option<&str>
                                .and_then(|ips_json| serde_json::from_str::<Vec<String>>(ips_json).ok())
                                .unwrap_or_default();

                            if !ip_list.contains(&address) {
                                ip_list.push(address.clone());
                            }

                            let ips_json = serde_json::to_string(&ip_list).unwrap_or_else(|_| "[]".into());

                            if existing.is_some() {
                                // update ips for existing player (and update name too)
                                sqlx::query!(
                                    r#"UPDATE players SET name = ?1, ips = ?2 WHERE uuid = ?3"#,
                                    player_name,
                                    ips_json,
                                    player_uuid
                                )
                                .execute(&pool)
                                .await?;
                            } else {
                                // insert new player
                                sqlx::query!(
                                    r#"INSERT INTO players (name, uuid, ips) VALUES (?1, ?2, ?3)"#,
                                    player_name,
                                    player_uuid,
                                    ips_json
                                )
                                .execute(&pool)
                                .await?;
                            }
                        }
                    }
                }
            }

            // Remove processed IP from ips table (uses column `ip`)
            sqlx::query!("DELETE FROM ips WHERE ip = ?1", address)
                .execute(&pool)
                .await?;
        }

        time::sleep(Duration::from_secs(1)).await;
    }
}

async fn get_ips(pool: &sqlx::SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query!("SELECT ip FROM ips")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|r| r.ip).collect())
}
