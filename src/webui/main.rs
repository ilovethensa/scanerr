use std::collections::HashMap;

use actix_web::{App, HttpResponse, HttpServer, Responder, get, web};
use scanerr::SortQuery;
use serde_json::json;
use tera::Tera;
use sqlx::SqlitePool;

pub struct AppState {
    pub tera: Tera,
    pub pool: SqlitePool,
}

#[get("/player/{id}")]
async fn player_detail(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();

    // Fetch the player
    let player = match scanerr::get_player(&state.pool, &id).await {
        Ok(Some(player)) => player,
        Ok(None) => return HttpResponse::NotFound().body("Player not found"),
        Err(_) => return HttpResponse::InternalServerError().body("Database error"),
    };

    let mut servers = Vec::new();

    // Fetch each server associated with the player
    for ip in &player.servers {
        match scanerr::get_server(&state.pool, ip).await {
            Ok(Some(server)) => servers.push(server),
            Ok(None) => (), // Server not found — just skip it
            Err(_) => (),   // DB error — skip
        }
    }

    let mut ctx = tera::Context::new();
    ctx.insert("player", &player);
    ctx.insert("servers", &servers);

    let body = state
        .tera
        .render("player.html", &ctx)
        .unwrap_or_else(|_| "Template error".to_string());

    HttpResponse::Ok().content_type("text/html").body(body)
}



#[get("/server/{ip}")]
async fn server_detail(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let ip = path.into_inner();

    let server = match scanerr::get_server(&state.pool, &ip).await {
        Ok(Some(s)) => s,
        Ok(None) => return HttpResponse::NotFound().body("Server not found"),
        Err(_) => return HttpResponse::InternalServerError().body("Database error"),
    };

    let server_players = match scanerr::get_players_by_server(&state.pool, &server.address).await {
        Ok(p) => p,
        Err(_) => vec![],
    };

    let mut ctx = tera::Context::new();
    ctx.insert("server", &server);
    ctx.insert("players", &server_players);

    let body = state
        .tera
        .render("server.html", &ctx)
        .unwrap_or_else(|_| "Template error".to_string());

    HttpResponse::Ok().content_type("text/html").body(body)
}


#[get("/")]
async fn index(
    state: web::Data<AppState>,
    query: web::Query<SortQuery>,
) -> impl Responder {
    let sort_by = query.sort.clone().unwrap_or_else(|| "newest".to_string());
    let order = query.order.clone().unwrap_or_else(|| "desc".to_string());

    let servers = match scanerr::get_servers(&state.pool, &sort_by, &order).await {
        Ok(s) => s,
        Err(err) => {
            eprintln!("Error fetching servers: {:?}", err);
            Vec::new()
        }
    };

    let mut ctx = tera::Context::new();
    ctx.insert("servers", &servers);
    ctx.insert("current_sort", &sort_by);
    ctx.insert("current_order", &order);

    let body = state
        .tera
        .render("index.html", &ctx)
        .unwrap_or_else(|e| {
            eprintln!("Template render error: {:?}", e);
            "Template error".to_string()
        });

    HttpResponse::Ok().content_type("text/html").body(body)
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let db_pool = SqlitePool::connect("sqlite://server.db")
        .await
        .expect("Failed to connect to database");

    let tera = Tera::new(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*"))
        .expect("Failed to initialize Tera templates");

    println!("Tera templates initialized.");

    let app_state = web::Data::new(AppState {
        tera,
        pool: db_pool.clone(),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(index)
            .service(player_detail)
            .service(server_detail)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
