use redis::aio::ConnectionManager;
use sqlx::PgPool;
use uuid::Uuid;

/// Per-instance state every admin handler reaches into.
///
/// `PgPool` and `ConnectionManager` are both internally `Arc`'d, so this
/// whole struct is cheap-Clone and we hand `State<AdminState>` directly
/// to axum handlers — no extra `Arc` wrapper.
#[derive(Clone)]
pub struct AdminState {
    pub pool: PgPool,
    pub kv: ConnectionManager,
    pub network_id: Uuid,
    pub network_name: String,
}
