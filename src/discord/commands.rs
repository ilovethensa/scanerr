use crate::{Context, Error};

/// Show this help menu
#[poise::command(prefix_command, track_edits, slash_command)]
pub async fn help(
    ctx: Context<'_>,
    #[description = "Specific command to show help about"]
    #[autocomplete = "poise::builtins::autocomplete_command"]
    command: Option<String>,
) -> Result<(), Error> {
    poise::builtins::help(
        ctx,
        command.as_deref(),
        poise::builtins::HelpConfiguration {
            extra_text_at_bottom: "This is an example bot made to showcase features of my custom Discord bot framework",
            ..Default::default()
        },
    )
    .await?;
    Ok(())
}


/// Displays bot statistics
#[poise::command(slash_command, prefix_command)]
pub async fn status(
    ctx: Context<'_>,
) -> Result<(), Error> {
    // Fetch total players online
    let players_count: i64 = sqlx::query_scalar!("SELECT SUM(players_online) FROM servers")
        .fetch_one(&*ctx.data().db_pool)
        .await
        .unwrap_or(Some(0))
        .unwrap_or(0);

    // Fetch total servers
    let servers_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM servers")
        .fetch_one(&*ctx.data().db_pool)
        .await
        .unwrap_or(0);

    let response = format!(
        "📊 **Bot Status**\n\
        Total Players Online: {}\n\
        Total Servers: {}",
        players_count, servers_count
    );

    ctx.say(response).await?;

    Ok(())
}

use serde_json::Value;

/// Gets server information for a given IP address
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

    let server = sqlx::query!(
        "SELECT * FROM servers WHERE address = ?",
        ip
    )
    .fetch_optional(&*ctx.data().db_pool)
    .await?;

    match server {
        Some(s) => {
            // Parse player list if available
            let players_list = if let Some(players_json) = &s.player_sample {
                match serde_json::from_str::<Vec<Value>>(players_json) {
                    Ok(players) => players
                        .iter()
                        .filter_map(|p| p.get("name"))
                        .filter_map(|n| n.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    Err(_) => "N/A".to_string(),
                }
            } else {
                "N/A".to_string()
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
                .execute(&*ctx.data().db_pool)
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

/// Lists latest servers with players online
#[poise::command(slash_command, prefix_command)]
pub async fn latestservers(ctx: Context<'_>) -> Result<(), Error> {
    let rows = sqlx::query!(
        "SELECT address, players_online, players_max FROM servers WHERE players_online > 0 ORDER BY id DESC LIMIT 10"
    )
    .fetch_all(&*ctx.data().db_pool)
    .await
    .unwrap_or_default();

    if rows.is_empty() {
        ctx.say("🖥 No Servers Found\nThere are currently no servers with players online.")
            .await?;
        return Ok(());
    }

    let mut desc = String::new();
    for r in rows.iter() {
        desc.push_str(&format!(
            "🔹 `{}` — **{}/{} players**\n",
            r.address,
            r.players_online.unwrap_or(0),
            r.players_max.unwrap_or(0)
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
pub async fn addip(
    ctx: Context<'_>,
    #[description = "The IP address to add"] ip: String,
) -> Result<(), Error> {
    let ip = ip.trim();

    if ip.is_empty() {
        ctx.say("❌ Error: Please provide an IP address.")
            .await?;
        return Ok(());
    }

    if let Err(e) = sqlx::query!("INSERT INTO ips (ip) VALUES (?)", ip)
        .execute(&*ctx.data().db_pool)
        .await
    {
        ctx.say(format!("❌ Database Error: {}", e)).await?;
        return Ok(());
    }

    ctx.say(format!("✅ IP Added\nIP `{}` has been added to the database.", ip))
        .await?;

    Ok(())
}

/// If no argument is provided, show the 10 latest players.
#[poise::command(slash_command, prefix_command)]
pub async fn getplayer(
    ctx: Context<'_>,
    #[description = "The player's name or UUID (optional). If omitted, returns the 10 latest players."] 
    player_identifier: Option<String>,
) -> Result<(), Error> {
    // If no argument -> show 10 latest players
    if player_identifier.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
        let rows = sqlx::query!(
            "SELECT name, uuid, ips FROM players ORDER BY id DESC LIMIT 10"
        )
        .fetch_all(&*ctx.data().db_pool)
        .await?;

        if rows.is_empty() {
            ctx.say("❌ No players found in the database.").await?;
            return Ok(());
        }

        let mut list = String::new();
        for (i, r) in rows.iter().enumerate() {
            list.push_str(&format!("{}. {} — `{}`\n", i + 1, r.name, r.uuid));
        }

        let resp = format!(
            "🕒 **Latest Players (most recent first)**\n{}\n\
            Use `/getplayer <exact_name>` or `/getplayer <uuid>` to view details.",
            list
        );
        ctx.say(resp).await?;
        return Ok(());
    }

    // Otherwise we have an identifier to search
    let id = player_identifier.unwrap().trim().to_string();
    if id.is_empty() {
        ctx.say("❌ Error: please provide a player name or UUID.").await?;
        return Ok(());
    }

    // 1) Try exact match by name OR uuid
    if let Some(p) = sqlx::query!(
        "SELECT name, uuid, ips FROM players WHERE name = ? OR uuid = ? LIMIT 1",
        id,
        id
    )
    .fetch_optional(&*ctx.data().db_pool)
    .await?
    {
        // Found exact match — show details
        let ips_text = match &p.ips {
            Some(j) => match serde_json::from_str::<Vec<String>>(j) {
                Ok(list) if !list.is_empty() => list.join(", "),
                _ => "No recorded IPs".to_string(),
            },
            None => "No recorded IPs".to_string(),
        };

        let resp = format!(
            "🧾 **Player Info**\n• Name: {}\n• UUID: `{}`\n• Known IPs: {}",
            p.name,
            p.uuid,
            ips_text
        );
        ctx.say(resp).await?;
        return Ok(());
    }

    // 2) Partial / fuzzy match (case-insensitive) on name
    let like_pattern = format!("%{}%", id);
    let rows = sqlx::query!(
        "SELECT name, uuid, ips FROM players WHERE name LIKE ? COLLATE NOCASE LIMIT 20",
        like_pattern
    )
    .fetch_all(&*ctx.data().db_pool)
    .await?;

    match rows.len() {
        0 => {
            ctx.say(format!("❌ Player `{}` not found.", id)).await?;
        }
        1 => {
            // Single partial match — show details
            let p = &rows[0];
            let ips_text = match &p.ips {
                Some(j) => match serde_json::from_str::<Vec<String>>(j) {
                    Ok(list) if !list.is_empty() => list.join(", "),
                    _ => "No recorded IPs".to_string(),
                },
                None => "No recorded IPs".to_string(),
            };

            let resp = format!(
                "🧾 **Player Info**\n• Name: {}\n• UUID: `{}`\n• Known IPs: {}",
                p.name,
                p.uuid,
                ips_text
            );
            ctx.say(resp).await?;
        }
        n => {
            // Multiple matches — show a short numbered list (up to 10) and hint how to get details
            let mut list = String::new();
            for (i, r) in rows.iter().take(10).enumerate() {
                list.push_str(&format!("{}. {} — `{}`\n", i + 1, r.name, r.uuid));
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
