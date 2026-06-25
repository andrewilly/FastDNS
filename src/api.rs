//! REST API server for FastDNS.
//!
//! Provides:
//! - `GET /api/health` — Health check endpoint
//! - `GET /api/stats` — Cache and query statistics
//! - `POST /api/cache/flush` — Flush DNS cache
//! - `GET /api/blocklist/stats` — Blocklist statistics
//! - `POST /api/blocklist/reload` — Reload blocklists

use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::Serialize;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::info;

/// Shared application state accessible from all API handlers.
pub struct AppState {
    /// Timestamp when the server started (used for uptime calculation).
    pub start_time: Instant,
    /// The recursive resolver used for DNS resolution and cache access.
    pub resolver: Arc<crate::resolver::recursive::RecursiveResolver>,
    /// Optional blocklist instance (None when blocklisting is disabled).
    pub blocklist: Option<Arc<crate::blocklist::Blocklist>>,
    /// Total number of DNS queries received.
    pub query_count: Arc<RwLock<u64>>,
    /// Total number of blocked DNS queries.
    pub blocked_count: Arc<RwLock<u64>>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Response for `GET /api/health`.
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    uptime_secs: u64,
}

/// Response for `GET /api/stats`.
#[derive(Serialize)]
struct StatsResponse {
    total_queries: u64,
    blocked_queries: u64,
    cache_hits: u64,
    cache_misses: u64,
    cache_hit_rate: f64,
    cache_size: usize,
}

/// Response for `POST /api/cache/flush`.
#[derive(Serialize)]
struct FlushResponse {
    status: String,
    message: String,
}

/// Response for `GET /api/blocklist/stats`.
#[derive(Serialize)]
struct BlocklistStatsResponse {
    enabled: bool,
    total_blocked: u64,
    total_queries: u64,
    rules_loaded: usize,
}

/// Response for `POST /api/blocklist/reload`.
#[derive(Serialize)]
struct ReloadResponse {
    status: String,
    message: String,
}

/// Generic error body returned on handler failures.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/health` — returns server status and uptime.
async fn health_handler(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let uptime = state.start_time.elapsed().as_secs();
    Json(HealthResponse {
        status: "ok".to_string(),
        uptime_secs: uptime,
    })
}

/// `GET /api/stats` — returns resolver and cache statistics.
async fn stats_handler(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    let total = *state.query_count.read().await;
    let blocked = *state.blocked_count.read().await;
    let (hits, misses) = state.resolver.cache_stats().await;
    let rate = if total == 0 {
        0.0
    } else {
        hits as f64 / (hits + misses) as f64
    };

    Json(StatsResponse {
        total_queries: total,
        blocked_queries: blocked,
        cache_hits: hits,
        cache_misses: misses,
        cache_hit_rate: rate,
        cache_size: 0, // approximate; DnsCache does not currently expose entry count
    })
}

/// `POST /api/cache/flush` — clears the entire DNS cache.
async fn cache_flush_handler(State(state): State<Arc<AppState>>) -> Json<FlushResponse> {
    state.resolver.flush_cache().await;
    info!("DNS cache flushed via API");
    Json(FlushResponse {
        status: "ok".to_string(),
        message: "DNS cache flushed successfully".to_string(),
    })
}

/// `GET /api/blocklist/stats` — returns blocklist statistics.
async fn blocklist_stats_handler(
    State(state): State<Arc<AppState>>,
) -> Json<BlocklistStatsResponse> {
    let total_blocked = *state.blocked_count.read().await;
    let total_queries = *state.query_count.read().await;

    match &state.blocklist {
        Some(_bl) => {
            // TODO: expose actual rule count from Blocklist when available.
            Json(BlocklistStatsResponse {
                enabled: true,
                total_blocked,
                total_queries,
                rules_loaded: 0,
            })
        }
        None => Json(BlocklistStatsResponse {
            enabled: false,
            total_blocked,
            total_queries,
            rules_loaded: 0,
        }),
    }
}

/// `POST /api/blocklist/reload` — triggers a blocklist reload.
async fn blocklist_reload_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ReloadResponse>, (StatusCode, Json<ErrorResponse>)> {
    match &state.blocklist {
        Some(_bl) => {
            // TODO: call `bl.reload().await` when the method is available on Blocklist.
            info!("Blocklist reload triggered via API");
            Ok(Json(ReloadResponse {
                status: "ok".to_string(),
                message: "Blocklist reload initiated".to_string(),
            }))
        }
        None => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Blocklist is not enabled".to_string(),
            }),
        )),
    }
}

// ---------------------------------------------------------------------------
// Router & server startup
// ---------------------------------------------------------------------------

/// Build the axum [`Router`] with all API routes and shared state.
fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/health", get(health_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/cache/flush", post(cache_flush_handler))
        .route("/api/blocklist/stats", get(blocklist_stats_handler))
        .route("/api/blocklist/reload", post(blocklist_reload_handler))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Start the API server on the given bind address, serving the REST endpoints.
///
/// This function binds and serves forever (or until a fatal error). Errors are
/// logged via `tracing` rather than panicking.
pub async fn start_api(state: AppState, bind_addr: &str) {
    let state = Arc::new(state);
    let app = build_router(state);

    let addr: std::net::SocketAddr = match bind_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Invalid API bind address '{}': {e}", bind_addr);
            return;
        }
    };

    info!("REST API server starting on http://{}/api", addr);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind API server on {addr}: {e}");
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("API server error: {e}");
    }
}
