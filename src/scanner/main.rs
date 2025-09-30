use sqlx::sqlite::SqlitePoolOptions;
use rand::Rng;
use rust_masscan::Masscan;
use tokio::{task, time};
use std::{collections::HashMap, time::{Duration, SystemTime, UNIX_EPOCH}};

/// Generate a random /16 or /20 IP range
fn random_ip_range() -> String {
    let mut rng = rand::thread_rng();
    let prefix = if rng.gen_bool(0.5) { 16 } else { 20 };
    format!(
        "{}.{}.0.0/{}",
        rng.gen_range(1..=255),
        rng.gen_range(0..=255),
        prefix
    )
}

/// Get subnets to scan, prioritizing unexplored or high-yield ones
async fn get_subnets_to_scan(pool: &sqlx::SqlitePool) -> Vec<(String, String)> {
    let addresses = match sqlx::query!("SELECT ip FROM ips")
        .fetch_all(pool)
        .await {
            Ok(addrs) => addrs,
            Err(_) => return vec![],
        };

    let mut subnet_counts: HashMap<String, usize> = HashMap::new();
    for row in addresses {
        let parts: Vec<&str> = row.ip.split('.').collect();
        if parts.len() >= 2 {
            let subnet = format!("{}.{}", parts[0], parts[1]);
            *subnet_counts.entry(subnet).or_insert(0) += 1;
        }
    }

    let mut subnets: Vec<(String, usize)> = subnet_counts.into_iter().collect();
    subnets.sort_by(|a, b| b.1.cmp(&a.1)); // Highest yield first

    let mut to_scan = Vec::new();

    for (subnet, _) in subnets.iter().take(10) {
        let parts: Vec<&str> = subnet.split('.').collect();
        if parts.len() >= 2 {
            let first_octet: u8 = parts[0].parse().unwrap_or(0);
            let second_octet: u8 = parts[1].parse().unwrap_or(0);

            for change in -5..=5 {
                let new_second = (second_octet as i16 + change).clamp(0, 255) as u8;
                for prefix in [16, 20] {
                    let pattern = format!("{}.{}.%", first_octet, new_second);

                    let existing: (i64, Option<i64>) = match sqlx::query_as(
                        "SELECT COUNT(*), MAX(last_scan) FROM subnet_scans WHERE subnet_pattern = ?"
                    )
                        .bind(&pattern)
                        .fetch_one(pool)
                        .await {
                            Ok(val) => val,
                            Err(_) => continue,
                        };

                    let cooldown = 24 * 3600;
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
                    let should_scan = existing.0 == 0 || existing.1.map_or(true, |last| now - last > cooldown);

                    if should_scan {
                        to_scan.push((
                            format!("{}.{}.0.0/{}", first_octet, new_second, "16"),
                            pattern.clone(),
                        ));
                    }
                }
            }
        }
    }

    if to_scan.is_empty() {
        to_scan.push((random_ip_range(), "".to_string()));
    }

    to_scan
}

/// Run Masscan and log results
async fn run_scan(pool: &sqlx::SqlitePool, ip_range: &str, subnet_pattern: &str) -> usize {
    println!("🔍 Scanning range: {}", ip_range);

    let ip_range_clone = ip_range.to_string();
    let results = task::spawn_blocking(move || {
        let other_args: Vec<String> = vec!["--banners".to_string()];

        let mas = Masscan::default()
            .set_system_path("/usr/bin/masscan".to_string())
            .set_ports("25565".to_string())
            .set_ranges(ip_range_clone.clone())
            .set_rate("10000".to_string())
            .set_other_args(other_args);

        mas.run().unwrap_or_default()
    })
    .await
    .unwrap();

    let mut found_count = 0;
    for info in results {
        if let Some(ip) = info.ip {
            let res = sqlx::query!(
                "INSERT OR IGNORE INTO ips (ip) VALUES (?)",
                ip
            )
            .execute(pool)
            .await;
            if res.is_ok() {
                found_count += 1;
            }
        }
    }

    // Log scan results to subnet_scans
    let lol = found_count as i64;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let _ = sqlx::query!(
        "INSERT INTO subnet_scans (subnet_pattern, last_scan, ips_found) VALUES (?, ?, ?)
        ON CONFLICT(subnet_pattern) DO UPDATE SET last_scan = excluded.last_scan, ips_found = excluded.ips_found",
        subnet_pattern,
        now,
        lol
    )
    .execute(pool)
    .await;

    println!("📊 Subnet {} found {} new IPs", subnet_pattern, found_count);
    found_count
}

/// Print scan summary
fn print_banner(ranges: &[String], total_ips: i64) {
    println!("\n══════════════════════════════════════════════");
    println!("🛰  Network Scan Summary");
    println!("Target Ranges:    {}", ranges.join(", "));
    println!("Total IPs Discovered: {}", total_ips);
    println!("══════════════════════════════════════════════\n");
}

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("./server.db")
        .await?;
    println!("✅ Connected to SQLITE!");

    sqlx::migrate!("./migrations").run(&pool).await?;
    println!("🛠 Migrations completed!");

    loop {
        let total_ips: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ips")
            .fetch_one(&pool)
            .await?;

        let mut to_scan = Vec::new();

        if total_ips.0 < 500 {
            // RANDOM scanning until we hit 500 IPs
            to_scan.push((random_ip_range(), "".to_string()));
        } else {
            // PRIORITIZED scanning after threshold
            to_scan = get_subnets_to_scan(&pool).await;
        }

        let mut scanned_ranges = Vec::new();
        for (range, pattern) in to_scan.iter() {
            run_scan(&pool, range, pattern).await;
            scanned_ranges.push(range.clone());
        }

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ips")
            .fetch_one(&pool)
            .await?;

        print_banner(&scanned_ranges, count.0);

        println!("💤 Sleeping for 30 minutes...");
        time::sleep(Duration::from_secs(1)).await;
    }
}
