use axum_util::errors::ApiResult;
use uuid::Uuid;

use crate::db::Conn;

#[derive(Debug)]
pub struct Favorite {
    pub user_uuid: Uuid,
    pub cipher_uuid: Uuid,
}

impl Favorite {
    // Returns whether the specified cipher is a favorite of the specified user.
    pub async fn is_favorite(conn: &Conn, cipher_uuid: Uuid, user_uuid: Uuid) -> ApiResult<bool> {
        Ok(conn.query_one(r"SELECT count(1) FROM favorites WHERE cipher_uuid = $1 AND user_uuid = $2", &[&cipher_uuid, &user_uuid]).await?.get::<_, i64>(0)
            != 0)
    }

    // Sets whether the specified cipher is a favorite of the specified user.
    pub async fn set_favorite(conn: &Conn, favorite: bool, cipher_uuid: Uuid, user_uuid: Uuid) -> ApiResult<()> {
        if favorite {
            conn.execute(
                "INSERT INTO favorites (cipher_uuid, user_uuid) VALUES ($1, $2) ON CONFLICT (user_uuid, cipher_uuid) DO NOTHING",
                &[&cipher_uuid, &user_uuid],
            )
            .await?;
        } else {
            conn.execute(r"DELETE FROM favorites WHERE cipher_uuid = $1 AND user_uuid = $2", &[&cipher_uuid, &user_uuid]).await?;
        }
        Ok(())
    }
}
