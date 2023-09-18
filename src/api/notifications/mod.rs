use std::{net::IpAddr, sync::Arc, time::Duration};

use anyhow::Result;
use axol::http::response::Response;
use axol::http::StatusCode;
use axol::{Error, Message, Query, Router, WebSocket, WebSocketUpgrade};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use log::{debug, error, info};
use rmpv::encode::write_value;
use rmpv::{decode::read_value, Value};
use serde::Deserialize;
use tokio::sync::mpsc::{self, Sender};
use uuid::Uuid;
use varint_rs::{VarintReader, VarintWriter};

use crate::{
    auth::ClientIp,
    db::{Cipher, Conn, Folder, Send as DbSend, User},
    CONFIG,
};

use once_cell::sync::Lazy;

static WS_USERS: Lazy<Arc<WebSocketUsers>> = Lazy::new(|| {
    Arc::new(WebSocketUsers {
        map: Arc::new(dashmap::DashMap::new()),
    })
});

pub fn ws_users() -> &'static Arc<WebSocketUsers> {
    &*WS_USERS
}

use crate::push::{push_cipher_update, push_folder_update, push_logout, push_send_update, push_user_update};

#[derive(Deserialize, Debug)]
struct WsAccessToken {
    access_token: Option<String>,
}

struct WSEntryMapGuard {
    users: Arc<WebSocketUsers>,
    user_uuid: Uuid,
    entry_uuid: Uuid,
    addr: IpAddr,
}

impl WSEntryMapGuard {
    fn new(users: Arc<WebSocketUsers>, user_uuid: Uuid, entry_uuid: Uuid, addr: IpAddr) -> Self {
        Self {
            users,
            user_uuid,
            entry_uuid,
            addr,
        }
    }
}

impl Drop for WSEntryMapGuard {
    fn drop(&mut self) {
        info!("Closing WS connection from {}", self.addr);
        if let Some(mut entry) = self.users.map.get_mut(&self.user_uuid) {
            entry.retain(|(uuid, _)| uuid != &self.entry_uuid);
        }
    }
}

pub fn route() -> Router {
    Router::new().get("/hub", start_websocket)
}

async fn start_websocket(Query(data): Query<WsAccessToken>, ip: ClientIp, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(|socket| async move {
        if let Err(e) = init_websocket(socket, data, ip).await {
            error!("ws error: {e}");
        }
    })
}

async fn init_websocket(ws: WebSocket, data: WsAccessToken, ip: ClientIp) -> Result<(), Error> {
    let addr = ip.ip;
    info!("Accepting WS connection from {addr}");

    let Some(token) = data.access_token else {
        err_code!("Invalid claim", StatusCode::Unauthorized)
    };
    let Ok(claims) = crate::auth::decode_login(&token) else {
        err_code!("Invalid token", StatusCode::Unauthorized)
    };

    let (rx, guard) = {
        let users = Arc::clone(&WS_USERS);

        // Add a channel to send messages to this client to the map
        let entry_uuid = Uuid::new_v4();
        let (tx, rx) = mpsc::channel::<Message>(100);
        users.map.entry(claims.sub.clone()).or_default().push((entry_uuid, tx));

        // Once the guard goes out of scope, the connection will have been closed and the entry will be deleted from the map
        (rx, WSEntryMapGuard::new(users, claims.sub, entry_uuid, addr))
    };

    if let Err(e) = run_websocket(ws, ip.ip, rx, guard).await {
        error!("[{}] websocket error: {e:#}", ip.ip);
    }
    debug!("[{}] closed", ip.ip);
    Ok(())
}

async fn run_websocket(mut ws: WebSocket, ip: IpAddr, mut rx: mpsc::Receiver<Message>, _guard: WSEntryMapGuard) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            res = ws.next() =>  {
                match res {
                    Some(Ok(message)) => {
                        match message {
                            // Respond to any pings
                            Message::Ping(ping) => {
                                debug!("[{}] received Ping message", ip);
                                ws.send(Message::Pong(ping)).await?;
                            },
                            Message::Pong(_) => {
                                debug!("[{}] received Pong message", ip);
                            },
                            Message::Binary(message) => {
                                debug!("[{}] received Binary message: {}", ip, hex::encode(&message));
                                let msg = match deserialize(&message) {
                                    Ok(x) => x,
                                    Err(e) => {
                                        error!("failed to decode inbound message: {e:#}");
                                        continue;
                                    }
                                };
                                let Value::Array(msg) = msg else {
                                    error!("invalid inbound message, not an array");
                                    continue;
                                };
                                if msg.get(0).and_then(|x| x.as_u64()) == Some(6) {
                                    // binary ping
                                    ws.send(Message::Binary(message)).await?;
                                } else {
                                    error!("unknown message Invokation");
                                }
                            },

                            // We should receive an initial message with the protocol and version, and we will reply to it
                            Message::Text(message) => {
                                debug!("[{}] received Text message: {message:?}", ip);
                                let msg = message.strip_suffix(RECORD_SEPARATOR as char).unwrap_or(&message);

                                if serde_json::from_str(msg).ok() == Some(INITIAL_MESSAGE) {
                                    debug!("responding with initial_response");
                                    ws.send(Message::Binary(INITIAL_RESPONSE.to_vec())).await?;
                                    continue;
                                }
                            }
                            Message::Close(_) => {
                                debug!("[{}] received Close message", ip);
                                break;
                            },
                        }
                    }
                    _ => break,
                }
            }

            res = rx.recv() => {
                match res {
                    Some(res) => {
                        if let Message::Binary(x) = &res {
                            debug!("[{ip}] sending message: {}", hex::encode(x));
                        }
                        ws.send(res).await?;
                    },
                    None => break,
                }
            }

            _ = interval.tick() => {
                debug!("[{}] sending Ping message", ip);
                ws.send(Message::Ping(create_ping())).await?
            },
        }
    }
    Ok(())
}

//
// Websockets server
//

fn serialize(val: Value) -> Vec<u8> {
    // reserve space for length
    let mut buf = vec![];
    write_value(&mut buf, &val).expect("Error encoding MsgPack");

    let mut lenbuf: Vec<u8> = Vec::with_capacity(buf.len() + 5);
    lenbuf.write_u32_varint(buf.len() as u32).unwrap();

    lenbuf.append(&mut buf);
    lenbuf
}

fn deserialize(mut val: &[u8]) -> Result<Value> {
    let len = val.read_u32_varint()?;
    let out = read_value(&mut &val[..len as usize])?;
    Ok(out)
}

fn serialize_date(date: DateTime<Utc>) -> Value {
    let seconds: i64 = date.timestamp();
    let nanos: i64 = date.timestamp_subsec_nanos().into();
    let timestamp = nanos << 34 | seconds;

    let bs = timestamp.to_be_bytes();

    // -1 is Timestamp
    // https://github.com/msgpack/msgpack/blob/master/spec.md#timestamp-extension-type
    Value::Ext(-1, bs.to_vec())
}

fn convert_option<T: Into<Value>>(option: Option<T>) -> Value {
    match option {
        Some(a) => a.into(),
        None => Value::Nil,
    }
}

const RECORD_SEPARATOR: u8 = 0x1e;
const INITIAL_RESPONSE: [u8; 3] = [0x7b, 0x7d, RECORD_SEPARATOR]; // {, }, <RS>

#[derive(Deserialize, Copy, Clone, Eq, PartialEq)]
struct InitialMessage<'a> {
    protocol: &'a str,
    version: i32,
}

static INITIAL_MESSAGE: InitialMessage<'static> = InitialMessage {
    protocol: "messagepack",
    version: 1,
};

// We attach the UUID to the sender so we can differentiate them when we need to remove them from the Vec
type UserSenders = (Uuid, Sender<Message>);
#[derive(Clone)]
pub struct WebSocketUsers {
    map: Arc<dashmap::DashMap<Uuid, Vec<UserSenders>>>,
}

impl WebSocketUsers {
    async fn send_update(&self, user_uuid: Uuid, data: &[u8]) {
        if let Some(user) = self.map.get(&user_uuid).map(|v| v.clone()) {
            for (_, sender) in user.iter() {
                if let Err(e) = sender.send(Message::Binary(data.to_vec())).await {
                    error!("Error sending WS update {e}");
                }
            }
        }
    }

    // NOTE: The last modified date needs to be updated before calling these methods
    pub async fn send_user_update(&self, ut: UpdateType, conn: &Conn, user: &User) -> Result<()> {
        let data =
            create_update(vec![("UserId".into(), user.uuid.to_string().into()), ("Date".into(), serialize_date(user.last_revision(conn).await?))], ut, None);

        self.send_update(user.uuid, &data).await;

        if CONFIG.push.is_some() {
            push_user_update(ut, user);
        }
        Ok(())
    }

    pub async fn send_logout(&self, user: &User, conn: &Conn, acting_device_uuid: Option<Uuid>) -> Result<()> {
        let data = create_update(
            vec![("UserId".into(), user.uuid.to_string().into()), ("Date".into(), serialize_date(user.last_revision(conn).await?))],
            UpdateType::LogOut,
            acting_device_uuid,
        );

        self.send_update(user.uuid, &data).await;

        if CONFIG.push.is_some() {
            push_logout(user, acting_device_uuid);
        }
        Ok(())
    }

    pub async fn send_folder_update(&self, ut: UpdateType, folder: &Folder, acting_device_uuid: Uuid, conn: &Conn) -> Result<()> {
        let data = create_update(
            vec![
                ("Id".into(), folder.uuid.to_string().into()),
                ("UserId".into(), folder.user_uuid.to_string().into()),
                ("RevisionDate".into(), serialize_date(folder.updated_at)),
            ],
            ut,
            Some(acting_device_uuid),
        );

        self.send_update(folder.user_uuid, &data).await;

        if CONFIG.push.is_some() {
            push_folder_update(ut, folder, acting_device_uuid, conn).await?;
        }
        Ok(())
    }

    pub async fn send_cipher_update_all(&self, ut: UpdateType, cipher: &Cipher, acting_device_uuid: Uuid, collection_uuids: Option<Vec<Uuid>>, conn: &Conn) {
        let users = match cipher.get_auth_users(conn).await {
            Ok(x) => x,
            Err(e) => {
                error!("failed to load users for cipher_update: {e}");
                return;
            }
        };
        if let Err(e) = self.send_cipher_update(ut, cipher, &users, acting_device_uuid, collection_uuids, conn).await {
            error!("failed to dispatch cipher_update: {e}");
        }
    }

    pub async fn send_cipher_update(
        &self,
        ut: UpdateType,
        cipher: &Cipher,
        user_uuids: &[Uuid],
        acting_device_uuid: Uuid,
        collection_uuids: Option<Vec<Uuid>>,
        conn: &Conn,
    ) -> Result<()> {
        let org_uuid = convert_option(cipher.organization_uuid.map(|x| x.to_string()));
        // Depending if there are collections provided or not, we need to have different values for the following variables.
        // The user_uuid should be `null`, and the revision date should be set to now, else the clients won't sync the collection change.
        let (user_uuid, collection_uuids, revision_date) = if let Some(collection_uuids) = collection_uuids {
            (Value::Nil, Value::Array(collection_uuids.into_iter().map(|v| v.to_string().into()).collect::<Vec<rmpv::Value>>()), serialize_date(Utc::now()))
        } else {
            (convert_option(cipher.user_uuid.map(|x| x.to_string())), Value::Nil, serialize_date(cipher.updated_at))
        };

        let data = create_update(
            vec![
                ("Id".into(), cipher.uuid.to_string().into()),
                ("UserId".into(), user_uuid),
                ("OrganizationId".into(), org_uuid),
                ("CollectionIds".into(), collection_uuids),
                ("RevisionDate".into(), revision_date),
            ],
            ut,
            Some(acting_device_uuid),
        );

        for uuid in user_uuids {
            self.send_update(*uuid, &data).await;
        }

        if CONFIG.push.is_some() && user_uuids.len() == 1 {
            push_cipher_update(ut, cipher, acting_device_uuid, conn).await?;
        }
        Ok(())
    }

    pub async fn send_send_update(&self, ut: UpdateType, send: &DbSend, user_uuids: &[Uuid], acting_device_uuid: Uuid, conn: &Conn) -> Result<()> {
        let user_uuid = convert_option(send.user_uuid.map(|x| x.to_string()));

        let data = create_update(
            vec![("Id".into(), send.uuid.to_string().into()), ("UserId".into(), user_uuid), ("RevisionDate".into(), serialize_date(send.revision_date))],
            ut,
            None,
        );

        for uuid in user_uuids {
            self.send_update(*uuid, &data).await;
        }
        if CONFIG.push.is_some() && user_uuids.len() == 1 {
            push_send_update(ut, send, acting_device_uuid, conn).await?;
        }
        Ok(())
    }
}

/* Message Structure
[
    1, // MessageType.Invocation
    {}, // Headers (map)
    null, // InvocationId
    "ReceiveMessage", // Target
    [ // Arguments
        {
            "ContextId": acting_device_uuid || Nil,
            "Type": ut as i32,
            "Payload": {}
        }
    ]
]
*/
fn create_update(payload: Vec<(Value, Value)>, ut: UpdateType, acting_device_uuid: Option<Uuid>) -> Vec<u8> {
    use rmpv::Value as V;

    let value = V::Array(vec![
        1.into(),
        V::Map(vec![]),
        V::Nil,
        "ReceiveMessage".into(),
        V::Array(vec![V::Map(vec![
            ("ContextId".into(), acting_device_uuid.map(|v| v.to_string().into()).unwrap_or_else(|| V::Nil)),
            ("Type".into(), (ut as i32).into()),
            ("Payload".into(), payload.into()),
        ])]),
    ]);

    serialize(value)
}

fn create_ping() -> Vec<u8> {
    serialize(Value::Array(vec![6.into()]))
}

#[allow(dead_code)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum UpdateType {
    SyncCipherUpdate = 0,
    SyncCipherCreate = 1,
    SyncLoginDelete = 2,
    SyncFolderDelete = 3,
    SyncCiphers = 4,

    SyncVault = 5,
    SyncOrgKeys = 6,
    SyncFolderCreate = 7,
    SyncFolderUpdate = 8,
    SyncCipherDelete = 9,
    SyncSettings = 10,

    LogOut = 11,

    SyncSendCreate = 12,
    SyncSendUpdate = 13,
    SyncSendDelete = 14,

    AuthRequest = 15,
    AuthRequestResponse = 16,

    None = 100,
}
