use anyhow::Result;
use clap::{Parser, Subcommand};
use sqlx::PgPool;
use tracing::{info, warn};

use scanerr::{config, db, enrich, fingerprint, masscan, probe, queue, serve};

#[derive(Parser)]
#[command(name = "scanerr", about = "Shodan-like service scanner for homelabbers")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run masscan discovery sweep — finds alive hosts, inserts into queue_host_scans
    Sweep,
    /// Run deep scan — claims alive hosts, masscan per-IP, inserts open ports into queue_service_probes
    Deepscan,
    Probe,
    Enrich,
    Serve,
    /// Run all stages in a single process (for local testing)
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

    // Test commands that don't need DB
    match &cli.command {
        Commands::TestScan { ip } => {
            let ports = config.scanner.expanded_deep_ports();
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
            let sig_dir = std::path::Path::new(&config.signatures.dir);
            let engine = fingerprint::Engine::from_dir(sig_dir);
            let data = probe::dispatch::probe_standalone(ip, port, &user_agent, &engine).await?;
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
        Commands::Sweep => {
            scanerr::normalize::backfill(&pool).await?;
            run_sweep(pool, config).await?
        }
        Commands::Deepscan => {
            scanerr::normalize::backfill(&pool).await?;
            run_deepscan(pool, config).await?
        }
        Commands::Probe => {
            let sig_dir = std::path::Path::new(&config.signatures.dir);
            let engine = fingerprint::Engine::from_dir(sig_dir);
            run_probe(pool, config, engine).await?
        }
        Commands::Enrich => run_enrich(pool, config).await?,
        Commands::Serve => run_serve(pool, config).await?,
        Commands::All => {
            let sig_dir = std::path::Path::new(&config.signatures.dir);
            let engine = fingerprint::Engine::from_dir(sig_dir);
            let config1 = config.clone();
            let config2 = config.clone();
            let config3 = config.clone();
            let config4 = config.clone();
            let pool2 = pool.clone();
            let pool3 = pool.clone();
            let pool4 = pool.clone();
            let pool5 = pool.clone();
            let engine2 = engine.clone();
            let h1 = tokio::spawn(run_sweep(pool, config));
            let h2 = tokio::spawn(run_deepscan(pool2, config1));
            let h3 = tokio::spawn(run_probe(pool3, config2, engine2));
            let h4 = tokio::spawn(run_enrich(pool4, config3));
            let h5 = tokio::spawn(run_serve(pool5, config4));
            h1.await??;
            h2.await??;
            h3.await??;
            h4.await??;
            h5.await??;
        }
        _ => unreachable!(),
    }

    Ok(())
}

async fn run_sweep(pool: PgPool, config: config::Config) -> Result<()> {
    info!("Starting sweep (masscan discovery)...");

    let scanner = config.scanner.clone();
    let ranges = scanner.ranges.clone();
    let ports = scanner.discovery_ports.clone();
    let rate = scanner.discovery_rate;
    let chunk_size = scanner.sweep_chunk_size;
    let interval = scanner.sweep_interval_secs;

    loop {
        for chunk in ranges.chunks(chunk_size) {
            // Wait while backpressured — retry the same chunk, never skip it
            loop {
                match queue::backpressure_active(&pool, scanner.max_probe_queue_depth).await {
                    Ok(true) => {
                        info!("Backpressure active — probe queue full, pausing sweep");
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    }
                    _ => break,
                }
            }

            info!("Sweeping {} ranges", chunk.len());
            let results = masscan::run_stage1_batch(chunk, &ports, rate)
                .unwrap_or_default();

            let mut inserted = 0u64;
            for result in &results {
                if let Err(e) = queue::insert_host_scan(&pool, &result.ip).await {
                    tracing::error!("Failed to insert host scan {}: {}", result.ip, e);
                } else {
                    inserted += 1;
                }
            }
            info!("Sweep chunk: found {} alive hosts, inserted {} into queue", results.len(), inserted);
        }

        info!("Sweep finished — all ranges scanned. Re-scanning in {}s", interval);
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    }
}

async fn run_deepscan(pool: PgPool, config: config::Config) -> Result<()> {
    info!("Starting deep scan...");

    let host_queue = queue::LeasedQueue::new("queue_host_scans");
    let ports = config.scanner.expanded_deep_ports();
    let rate = config.scanner.deep_scan_rate;

    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    };

    loop {
        let t = now();

        let items = host_queue.claim_host_scans(&pool, 10, t).await
            .unwrap_or_default();

        if items.is_empty() {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }

        for (id, ip_str) in &items {
            info!("Deep scanning {}", ip_str);
            let results = masscan::run_stage2(ip_str, &ports, rate)
                .unwrap_or_default();

            let threshold = config.scanner.honeypot_port_threshold;
            if results.len() as u32 > threshold {
                warn!(
                    "Skipping {} — {} open ports exceeds honeypot threshold ({})",
                    ip_str, results.len(), threshold
                );
                let _ = sqlx::query(
                    "UPDATE hosts SET is_honeypot = true WHERE ip = $1",
                )
                .bind(ip_str)
                .execute(&pool)
                .await;
                let _ = host_queue.complete(&pool, *id).await;
                continue;
            }

            for result in &results {
                if let Err(e) = queue::insert_service_probe(&pool, &result.ip, result.port as i32, "tcp").await {
                    tracing::error!("Failed to insert service probe: {}", e);
                }
            }
            info!("Deep scan {}: found {} open ports", ip_str, results.len());

            let _ = host_queue.heartbeat(&pool, *id, now()).await;
            let _ = host_queue.complete(&pool, *id).await;
        }
    }
}

async fn run_probe(pool: PgPool, config: config::Config, engine: fingerprint::Engine) -> Result<()> {
    info!("Starting probe stage...");
    let probe_queue = queue::LeasedQueue::new("queue_service_probes");
    let user_agent = config.probe.user_agent.clone();
    let geoip_db = config.probe.geoip_db_path.clone();
    let probe_timeout = std::time::Duration::from_secs(config.probe.timeout_secs);

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

            match tokio::time::timeout(
                probe_timeout,
                probe::dispatch::probe(
                    &pool,
                    &ip_str,
                    port as u16,
                    &transport,
                    &user_agent,
                    geoip_db.as_deref(),
                    &engine,
                ),
            ).await {
                Ok(Ok(result)) => {
                    match probe::dispatch::upsert_service(&pool, &result).await {
                        Ok(service_id) => {
                            let _ = probe::dispatch::maybe_enqueue_enrichments(
                                &pool, service_id, &result.data,
                            ).await;
                            info!("Probed {}:{} -> service_id={}", ip_str, port, service_id);
                        }
                        Err(e) => tracing::error!("Failed to upsert service: {}", e),
                    }
                    let _ = probe_queue.complete(&pool, id).await;
                }
                Ok(Err(e)) => {
                    tracing::error!("Probe failed for {}:{}: {}", ip_str, port, e);
                    let _ = probe_queue.complete(&pool, id).await;
                }
                Err(_) => {
                    tracing::warn!("Probe timed out for {}:{}", ip_str, port);
                    let _ = probe_queue.complete(&pool, id).await;
                }
            }
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
                "rtsp_frame" => Some(enrich::EnricherKind::RtspFrame),
                "camera_frame" => Some(enrich::EnricherKind::CameraFrame),
                _ => None,
            };

            if let Some(e) = enricher {
                if let Err(err) = e.run(&pool, service_id, &assets_dir).await {
                    tracing::error!("Enrichment failed for service {}: {}", service_id, err);
                }
            }

            let _ = enrich_queue.heartbeat(&pool, id, now()).await;
            let _ = enrich_queue.complete(&pool, id).await;
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
