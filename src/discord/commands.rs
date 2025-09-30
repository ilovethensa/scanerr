use crate::{Context, Error};
use scanerr::{get_latest_players, get_latest_servers, get_player_from_db, get_server_with_players, get_status_data, search_player};


#[poise::command(slash_command, prefix_command)]
pub async fn status(ctx: Context<'_>) -> Result<(), Error> {
    let db_pool = &*ctx.data().db_pool;

    let (players_count, servers_count) = get_status_data(db_pool).await?;

    let response = format!(
        "📊 **Bot Status**\n\
        Total Players Online: {}\n\
        Total Servers: {}",
        players_count, servers_count
    );

    ctx.say(response).await?;
    Ok(())
}


#[poise::command(slash_command, prefix_command)]
pub async fn getserver(
    ctx: Context<'_>,
    #[description = "IP address of the server"] ip: String,
) -> Result<(), Error> {
    let ip = ip.trim();

    if ip.is_empty() {
        ctx.say("❌ Error: Please provide an IP address.").await?;
        return Ok(());
    }

    let db_pool = &*ctx.data().db_pool;

    match get_server_with_players(db_pool, ip).await? {
        Some(server_with_players) => {
            let s = server_with_players.server;

            let players_list = if server_with_players.players.is_empty() {
                "N/A".to_string()
            } else {
                server_with_players
                    .players
                    .iter()
                    .map(|p| p.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            };

            let response = format!(
                "🖥 **Server Info — {}**\n\
                Address: `{}`\n\
                Hostname: `{}`\n\
                Version: `{}`\n\
                Players: `{}/{}`\n\
                Player List: `{}`\n\
                Description: `{}`\n\
                Gamemode: `{}`\n\
                Software: `{}`",
                ip,
                s.address,
                s.hostname.as_deref().unwrap_or("N/A"),
                s.version_name.as_deref().unwrap_or("N/A"),
                s.players_online.unwrap_or(0),
                s.players_max.unwrap_or(0),
                players_list,
                s.description.as_deref().unwrap_or("N/A"),
                s.gamemode.as_deref().unwrap_or("N/A"),
                s.software.as_deref().unwrap_or("N/A"),
            );

            ctx.say(response).await?;
        }
        None => {
            // Add IP to database for scanning
            if let Err(e) = sqlx::query!("INSERT INTO ips (ip) VALUES (?)", ip)
                .execute(db_pool)
                .await
            {
                ctx.say(format!("❌ Database Error: Could not add IP: {}", e))
                    .await?;
                return Ok(());
            }

            ctx.say(format!(
                "ℹ️ Server `{}` not found. IP has been added for scanning.",
                ip
            ))
            .await?;
        }
    }

    Ok(())
}


#[poise::command(slash_command, prefix_command)]
pub async fn latestservers(ctx: Context<'_>) -> Result<(), Error> {
    let db_pool = &*ctx.data().db_pool;

    let servers = get_latest_servers(db_pool).await?;

    if servers.is_empty() {
        ctx.say("🖥 No Servers Found\nThere are currently no servers with players online.")
            .await?;
        return Ok(());
    }

    let mut desc = String::new();
    for server in servers {
        desc.push_str(&format!(
            "🔹 `{}` — **{}/{} players**\n",
            server.address,
            server.players_online.unwrap_or(0),
            server.players_max.unwrap_or(0)
        ));
    }

    let message = format!(
        "🖥 **Latest Servers**\nHere are the latest servers with players online:\n{}",
        desc
    );

    ctx.say(message).await?;
    Ok(())
}



#[poise::command(slash_command, prefix_command)]
pub async fn getplayer(
    ctx: Context<'_>,
    #[description = "The player's name or UUID (optional). If omitted, returns the 10 latest players."]
    player_identifier: Option<String>,
) -> Result<(), Error> {
    let db_pool = &*ctx.data().db_pool;

    // If no argument -> show 10 latest players
    if player_identifier.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
        let rows = get_latest_players(db_pool).await?;

        if rows.is_empty() {
            ctx.say("❌ No players found in the database.").await?;
            return Ok(());
        }

        let mut list = String::new();
        for (i, player) in rows.iter().enumerate() {
            list.push_str(&format!("{}. {} — `{}`\n", i + 1, player.name, player.uuid));
        }

        let resp = format!(
            "🕒 **Latest Players (most recent first)**\n{}\n\
            Use `/getplayer <exact_name>` or `/getplayer <uuid>` to view details.",
            list
        );
        ctx.say(resp).await?;
        return Ok(());
    }

    let id = player_identifier.unwrap().trim().to_string();
    if id.is_empty() {
        ctx.say("❌ Error: please provide a player name or UUID.").await?;
        return Ok(());
    }

    // Try exact match
    if let Some(player) = get_player_from_db(db_pool, &id).await? {
        let ips_text = match &player.ips {
            Some(j) => match serde_json::from_str::<Vec<String>>(j) {
                Ok(list) if !list.is_empty() => list.join(", "),
                _ => "No recorded IPs".to_string(),
            },
            None => "No recorded IPs".to_string(),
        };

        let resp = format!(
            "🧾 **Player Info**\n• Name: {}\n• UUID: `{}`\n• Known IPs: {}",
            player.name, player.uuid, ips_text
        );
        ctx.say(resp).await?;
        return Ok(());
    }

    // Partial / fuzzy match
    let players = search_player(db_pool, &id).await?;
    match players.len() {
        0 => {
            ctx.say(format!("❌ Player `{}` not found.", id)).await?;
        }
        1 => {
            let player = &players[0];
            let ips_text = match &player.ips {
                Some(j) => match serde_json::from_str::<Vec<String>>(j) {
                    Ok(list) if !list.is_empty() => list.join(", "),
                    _ => "No recorded IPs".to_string(),
                },
                None => "No recorded IPs".to_string(),
            };

            let resp = format!(
                "🧾 **Player Info**\n• Name: {}\n• UUID: `{}`\n• Known IPs: {}",
                player.name, player.uuid, ips_text
            );
            ctx.say(resp).await?;
        }
        n => {
            let mut list = String::new();
            for (i, player) in players.iter().take(10).enumerate() {
                list.push_str(&format!("{}. {} — `{}`\n", i + 1, player.name, player.uuid));
            }
            if n > 10 {
                list.push_str(&format!("...and {} more\n", n - 10));
            }

            let resp = format!(
                "❗ Multiple players matched `{}` ({} results):\n{}\n\
                Use `/getplayer <exact_name>` or `/getplayer <uuid>` to view one player's details.",
                id, n, list
            );
            ctx.say(resp).await?;
        }
    }

    Ok(())
}
