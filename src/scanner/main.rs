use sqlx::sqlite::SqlitePoolOptions;
use rand::Rng;
use rust_masscan::Masscan;
use tokio::{task, time};
use std::time::Duration;

fn random_ip_range() -> String {
    let mut rng = rand::rng();
    format!(
        "{}.{}.0.0/16",
        rng.random_range(1..=255),
        rng.random_range(0..=255)
    )
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

    loop {
        let results = task::spawn_blocking(move || {
            let other_args: Vec<String> = vec!["--banners".to_string()];
            let ip_range = random_ip_range();
            println!("Scanning IP Range: {}", ip_range);

            let mas = Masscan::default()
                .set_system_path("/usr/bin/masscan".to_string())
                .set_ports("25565".to_string())
                .set_ranges(ip_range)
                .set_rate("10000".to_string())
                .set_other_args(other_args);

            mas.run().unwrap_or_default()
        })
        .await
        .unwrap();

        for info in results {
            if let Some(ip) = info.ip {
                sqlx::query!(
                    "INSERT INTO ips (ip) VALUES (?)",
                    ip
                )
                .execute(&pool)
                .await?;
            }
        }
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ips")
            .fetch_one(&pool)
            .await?;
        println!("Total scanned IPs in DB: {}", count.0);
        println!("Sleeping for 30 minutes...");

        time::sleep(Duration::from_secs(1)).await;
    }
}
