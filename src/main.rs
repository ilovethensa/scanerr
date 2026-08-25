use anyhow::Result;
use clap::{Parser, Subcommand};
use sqlx::PgPool;
use tracing::info;

use scanerr::{config, db, enrich, masscan, probe, queue, serve};

#[derive(Parser)]
#[command(name = "scanerr", about = "Shodan-like service scanner for homelabbers")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan,
    Probe,
    Enrich,
    Serve,
    All,
    /// Test: deep-scan a single IP
    TestScan {
        /// IP address to scan (e.g. 192.168.1.1)
        ip: String,
    },
    /// Test: probe a single ip:port (no DB needed)
    TestProbe {
        /// Target as ip:port (e.g. 192.168.1.1:80)
        target: String,
    },
    /// Test: run masscan sweep on a CIDR and print alive hosts
    TestSweep {
        /// CIDR range (e.g. 192.168.1.0/24)
        cidr: String,
    },
    /// Test: run standalone enrichment (no DB needed)
    TestEnrich {
        /// Enrichment type (e.g. favicon, geoip)
        kind: String,
        /// Target — meaning depends on type (URL for favicon, IP for geoip)
        target: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider before any TLS operations
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let config = config::load("scanerr.toml").unwrap_or_else(|_| config::Config::default());
    let pool = db::connect(&config.database.url).await?;
    db::run_migrations(&pool).await?;

    match &cli.command {
        Commands::TestScan { ip } => {
            let ports = config.scanner.deep_scan_ports.clone();
            let rate = config.scanner.deep_scan_rate;
            let results = masscan::run_stage2(ip, &ports, rate)?;
            for r in &results {
                println!("{}:{}", r.ip, r.port);
            }
            println!("Found {} open ports on {}", results.len(), ip);
            return Ok(());
        }
        Commands::TestProbe { target } => {
            let parts: Vec<&str> = target.split(':').collect();
            if parts.len() != 2 {
                anyhow::bail!("expected ip:port, got {}", target);
            }
            let ip = parts[0];
            let port: u16 = parts[1].parse()?;
            let user_agent = config.probe.user_agent.clone();
            let data = probe::dispatch::probe_standalone(ip, port, &user_agent).await?;
            println!("{}", serde_json::to_string_pretty(&data)?);
            return Ok(());
        }
        Commands::TestSweep { cidr } => {
            let ports = config.scanner.discovery_ports.clone();
            let rate = config.scanner.discovery_rate;
            let results = masscan::run_stage1(cidr, &ports, rate)?;
            for r in &results {
                println!("{}", r.ip);
            }
            println!("Found {} alive hosts in {}", results.len(), cidr);
            return Ok(());
        }
        Commands::TestEnrich { kind, target } => {
            let output = enrich::run_standalone(&kind, &target).await?;
            println!("{}", output);
            return Ok(());
        }
        _ => {}
    }

    let pool = db::connect(&config.database.url).await?;
    db::run_migrations(&pool).await?;

    match cli.command {
        Commands::Scan => run_scan(pool, config).await?,
        Commands::Probe => run_probe(pool, config).await?,
        Commands::Enrich => run_enrich(pool, config).await?,
        Commands::Serve => run_serve(pool, config).await?,
        Commands::All => {
            let config1 = config.clone();
            let config2 = config.clone();
            let config3 = config.clone();
            let pool2 = pool.clone();
            let pool3 = pool.clone();
            let pool4 = pool.clone();
            let h1 = tokio::spawn(run_scan(pool, config));
            let h2 = tokio::spawn(run_probe(pool2, config1));
            let h3 = tokio::spawn(run_enrich(pool3, config2));
            let h4 = tokio::spawn(run_serve(pool4, config3));
            h1.await??;
            h2.await??;
            h3.await??;
            h4.await??;
        }
        _ => unreachable!(),
    }

    Ok(())
}

async fn run_scan(pool: PgPool, config: config::Config) -> Result<()> {
    info!("Starting scan stage...");

    let host_queue = queue::LeasedQueue::new("queue_host_scans");
    let scanner = config.scanner.clone();
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    };

    // Stage 1: Broad sweep — lease subnets, run masscan, insert alive IPs
    let sweep_pool = pool.clone();
    let sweep_ranges = scanner.ranges.clone();
    let sweep_ports = scanner.discovery_ports.clone();
    let sweep_rate = scanner.discovery_rate;
    let max_depth = scanner.max_probe_queue_depth;
    let sweep_handle = tokio::spawn(async move {
        for range in &sweep_ranges {
            // Check backpressure before scanning
            if queue::backpressure_active(&sweep_pool, max_depth).await.unwrap_or(false) {
                info!("Backpressure active — probe queue full, pausing sweep");
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            }

            info!("Sweeping CIDR: {}", range);
            let results = masscan::run_stage1(range, &sweep_ports, sweep_rate)
                .unwrap_or_default();

            let mut inserted = 0u64;
            for result in &results {
                if let Err(e) = queue::insert_host_scan(&sweep_pool, &result.ip).await {
                    tracing::error!("Failed to insert host scan {}: {}", result.ip, e);
                } else {
                    inserted += 1;
                }
            }
            info!("Sweep {}: found {} alive hosts, inserted {} into queue", range, results.len(), inserted);
        }
    });

    // Stage 2: Deep scan — claim IPs, run masscan per-IP, insert open ports
    let deep_pool = pool.clone();
    let deep_ports = scanner.deep_scan_ports.clone();
    let deep_rate = scanner.deep_scan_rate;
    let deep_handle = tokio::spawn(async move {
        loop {
            let t = now();

            let items = host_queue.claim_host_scans(&deep_pool, 10, t).await
                .unwrap_or_default();

            if items.is_empty() {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            for (id, ip_str) in &items {
                info!("Deep scanning {}", ip_str);
                let results = masscan::run_stage2(ip_str, &deep_ports, deep_rate)
                    .unwrap_or_default();

                for result in &results {
                    if let Err(e) = queue::insert_service_probe(&deep_pool, &result.ip, result.port as i32, "tcp").await {
                        tracing::error!("Failed to insert service probe: {}", e);
                    }
                }
                info!("Deep scan {}: found {} open ports", ip_str, results.len());

                let _ = host_queue.heartbeat(&deep_pool, *id, now()).await;
            }
        }
    });

    sweep_handle.await?;
    deep_handle.await?;

    Ok(())
}

async fn run_probe(pool: PgPool, config: config::Config) -> Result<()> {
    info!("Starting probe stage...");
    let probe_queue = queue::LeasedQueue::new("queue_service_probes");
    let user_agent = config.probe.user_agent.clone();
    let geoip_db = config.probe.geoip_db_path.clone();

    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    };

    loop {
        let t = now();

        let items = probe_queue.claim_service_probes(&pool, 10, t).await
            .unwrap_or_default();

        if items.is_empty() {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }

        for (id, ip_str, port, transport) in items {
            info!("Probing {}:{}", ip_str, port);

            match probe::dispatch::probe(
                &pool,
                &ip_str,
                port as u16,
                &transport,
                &user_agent,
                geoip_db.as_deref(),
            ).await {
                Ok(result) => {
                    match probe::dispatch::upsert_service(&pool, &result).await {
                        Ok(service_id) => {
                            let _ = probe::dispatch::maybe_enqueue_enrichments(
                                &pool, service_id, &result.data,
                            ).await;
                            info!("Probed {}:{} -> service_id={}", ip_str, port, service_id);
                        }
                        Err(e) => tracing::error!("Failed to upsert service: {}", e),
                    }
                }
                Err(e) => tracing::error!("Probe failed for {}:{}: {}", ip_str, port, e),
            }

            let _ = probe_queue.heartbeat(&pool, id, now()).await;
        }
    }
}

async fn run_enrich(pool: PgPool, config: config::Config) -> Result<()> {
    info!("Starting enrich stage...");
    let enrich_queue = queue::LeasedQueue::new("queue_enrichments");
    let assets_dir = config.storage.assets_dir.clone();

    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    };

    loop {
        let t = now();

        let items = enrich_queue.claim_enrichments(&pool, 10, t).await
            .unwrap_or_default();

        if items.is_empty() {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }

        for (id, service_id, kind) in items {
            info!("Enriching service {} with {}", service_id, kind);

            let enricher = match kind.as_str() {
                "favicon" => Some(enrich::EnricherKind::Favicon),
                _ => None,
            };

            if let Some(e) = enricher {
                if let Err(err) = e.run(&pool, service_id, &assets_dir).await {
                    tracing::error!("Enrichment failed for service {}: {}", service_id, err);
                }
            }

            let _ = enrich_queue.heartbeat(&pool, id, now()).await;
        }
    }
}

async fn run_serve(pool: PgPool, config: config::Config) -> Result<()> {
    info!("Starting web server on {}", config.webui.bind);

    let tera = tera::Tera::new(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*"))
        .expect("Failed to initialize Tera templates");

    let app = serve::create_router(pool, tera);

    let listener = tokio::net::TcpListener::bind(&config.webui.bind).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
