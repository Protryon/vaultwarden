use axol::{ErrorExt, Result};

use crate::db::Conn;

#[derive(Debug)]
pub struct Invitation {
    pub email: String,
}

impl Invitation {
    pub fn new(email: &str) -> Self {
        let email = email.to_lowercase();
        Self {
            email,
        }
    }

    pub async fn save(&self, conn: &Conn) -> Result<()> {
        if self.email.trim().is_empty() {
            err!("Invitation email can't be empty")
        }
        conn.execute("INSERT INTO invitations (email) VALUES ($1) ON CONFLICT (email) DO NOTHING", &[&self.email]).await.ise()?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> Result<()> {
        conn.execute("DELETE FROM invitations WHERE email = $1", &[&self.email]).await.ise()?;
        Ok(())
    }

    pub async fn find_by_email(conn: &Conn, email: &str) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM invitations WHERE email = $1", &[&email]).await.ise()?.map(|x| Invitation {
            email: x.get(0),
        }))
    }

    pub async fn take(conn: &Conn, email: &str) -> Result<bool> {
        match Self::find_by_email(conn, email).await.ise()? {
            Some(invitation) => {
                invitation.delete(conn).await.ise()?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}
