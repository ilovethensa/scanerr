use serde::{Deserialize, Serialize};
use sqlx::{Error, Pool, Sqlite};

#[derive(Serialize, sqlx::FromRow, Debug)]
pub struct Player {
    pub id: i64,
    pub name: String,
    pub uuid: String,
    pub servers: Vec<String>,
}

#[derive(Serialize, sqlx::FromRow, Debug)]
pub struct Server {
    pub id: i64,
    pub address: String,
    pub players_online: Option<i64>,

    // optional fields from the old UI:
    pub players_max: Option<i64>,
    pub version_name: Option<String>,
    pub hostname: Option<String>,

    // raw favicon payload (either "data:..." or plain base64)
    pub favicon: Option<String>,

    pub created_at: Option<String>, // when row was added
    pub scanned_at: Option<String>, // last scanned time
}

#[derive(Deserialize)]
pub struct SortQuery {
    pub sort: Option<String>,
    pub order: Option<String>,
}

pub async fn get_player(
    db: &Pool<Sqlite>,
    id: &str,
) -> Result<Option<Player>, Error> {
    let row = sqlx::query!(
        "SELECT id, name, uuid, servers FROM players WHERE name = ? OR uuid = ? LIMIT 1",
        id, id
    )
    .fetch_optional(db)
    .await?;

    Ok(row.map(|r| Player {
        id: r.id,
        name: r.name,
        uuid: r.uuid,
        servers: r.servers
            .map(|s| serde_json::from_str(&s).unwrap_or_default())
            .unwrap_or_default(),
    }))
}

pub async fn get_servers(
    db: &Pool<Sqlite>,
    sort_by: &str,
    order: &str,
) -> Result<Vec<Server>, sqlx::Error> {
    let order = if order.eq_ignore_ascii_case("asc") { "ASC" } else { "DESC" };

    let sort_column = match sort_by {
        "players" => "players_online",
        "newest" => "added_at",
        _ => "added_at",
    };

    let query = format!(
        "SELECT id, address, players_online, players_max, version_name, hostname, favicon, added_at as created_at, scanned_at 
         FROM servers 
         ORDER BY {} {} LIMIT 100",
        sort_column, order
    );

    sqlx::query_as::<_, Server>(&query)
        .fetch_all(db)
        .await
}


pub async fn add_player(
    db: &Pool<Sqlite>,
    name: &str,
    uuid: &str,
    server_ip: &str,
) -> Result<(), Error> {
    // Fetch existing player
    let existing = sqlx::query!(
        "SELECT servers FROM players WHERE uuid = ?",
        uuid
    )
    .fetch_optional(db)
    .await?;

    let mut servers: Vec<String> = existing
        .as_ref()
        .and_then(|r| r.servers.clone())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    // Append if not already in list
    if !servers.contains(&server_ip.to_string()) {
        servers.push(server_ip.to_string());
    }

    let servers_json = serde_json::to_string(&servers).unwrap_or_else(|_| "[]".to_string());

    if existing.is_some() {
        // Update existing player
        sqlx::query!(
            "UPDATE players SET name = ?, servers = ?, scanned_at = CURRENT_TIMESTAMP WHERE uuid = ?",
            name,
            servers_json,
            uuid
        )
        .execute(db)
        .await?;
    } else {
        // Insert new player
        sqlx::query!(
            "INSERT INTO players (name, uuid, servers) VALUES (?, ?, ?)",
            name,
            uuid,
            servers_json
        )
        .execute(db)
        .await?;
    }

    Ok(())
}

pub async fn get_server(
    db: &Pool<Sqlite>,
    ip: &str,
) -> Result<Option<Server>, sqlx::Error> {
    let row = sqlx::query_as!(
        Server,
        r#"
        SELECT 
            id, 
            address, 
            players_online, 
            players_max, 
            version_name, 
            hostname, 
            favicon, 
            CAST(added_at AS TEXT) AS created_at, 
            CAST(scanned_at AS TEXT) AS scanned_at
        FROM servers 
        WHERE address = ?
        LIMIT 1
        "#,
        ip
    )
    .fetch_optional(db)
    .await?;

    Ok(row)
}

pub async fn get_players_by_server(
    db: &Pool<Sqlite>,
    server_ip: &str,
) -> Result<Vec<Player>, Error> {
    let pattern = format!("%{}%", server_ip); // store in a variable

    let rows = sqlx::query!(
        "SELECT id, name, uuid, servers FROM players WHERE servers LIKE ?",
        pattern
    )
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Player {
            id: r.id,
            name: r.name,
            uuid: r.uuid,
            servers: r.servers
                .map(|s| serde_json::from_str(&s).unwrap_or_default())
                .unwrap_or_default(),
        })
        .collect())
}
