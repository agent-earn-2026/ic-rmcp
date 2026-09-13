//! Self-service API key management for Prometheus MCP servers.
//!
//! A Rust port of the Motoko `ApiKey.mo` module. Lets any caller generate,
//! list, and revoke their own API keys for non-interactive authentication.
//!
//! Keys are stored only as SHA-256 hashes; the raw key is returned to the
//! caller exactly once at creation time and never persisted.

use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::time;
use ic_cdk::management_canister::raw_rand;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;

/// A type alias for the SHA-256 hash of an API key, hex-encoded.
pub type HashedApiKey = String;

/// Metadata associated with a stored API key.
#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct ApiKeyInfo {
    /// The principal this key acts on behalf of.
    pub principal: Principal,
    /// The permissions granted by this key.
    pub scopes: Vec<String>,
    /// A human-readable name for the key (e.g. "Analytics Service").
    pub name: String,
    /// When the key was created (nanoseconds since epoch).
    pub created: u64,
}

/// Public metadata returned when listing keys (hash + info).
#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct ApiKeyMetadata {
    pub hashed_key: HashedApiKey,
    pub info: ApiKeyInfo,
}

/// State for the API key module: the set of issued keys plus the canister owner.
#[derive(Default)]
pub struct ApiKeyState {
    /// The principal authorized to manage API keys.
    pub owner: Option<Principal>,
    /// Maps a key's SHA-256 hash to its info. Raw keys are never stored.
    pub api_keys: HashMap<HashedApiKey, ApiKeyInfo>,
}

thread_local! {
    static API_KEY_STATE: RefCell<ApiKeyState> = RefCell::new(ApiKeyState::default());
}

/// Initialize the API key module, recording the canister owner.
pub fn init(owner: Principal) {
    API_KEY_STATE.with_borrow_mut(|s| s.owner = Some(owner));
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex_encode(&h.finalize())
}

/// Create a new API key owned by `caller`.
///
/// Generates 32 random bytes via the IC's `raw_rand`, stores only the SHA-256
/// hash, and returns the raw (unhashed) hex key to the caller. The raw key is
/// shown once and never stored.
///
/// The key is always bound to `caller`, preventing impersonation.
pub async fn create_my_api_key(
    caller: Principal,
    name: String,
    scopes: Vec<String>,
) -> Result<String, String> {
    let raw = raw_rand()
        .await
        .map_err(|e| format!("raw_rand failed: {e}"))?;
    let raw_key = hex_encode(&raw);
    let hashed = sha256_hex(&raw);

    let info = ApiKeyInfo {
        principal: caller,
        scopes,
        name,
        created: time(),
    };

    API_KEY_STATE.with_borrow_mut(|s| {
        s.api_keys.insert(hashed, info);
    });

    Ok(raw_key)
}

/// List metadata for every API key owned by `caller`.
///
/// Only keys whose `principal` matches `caller` are returned.
pub fn list_my_api_keys(caller: Principal) -> Vec<ApiKeyMetadata> {
    API_KEY_STATE.with_borrow(|s| {
        s.api_keys
            .iter()
            .filter(|(_, info)| info.principal == caller)
            .map(|(hash, info)| ApiKeyMetadata {
                hashed_key: hash.clone(),
                info: info.clone(),
            })
            .collect()
    })
}

/// Revoke an API key owned by `caller`.
///
/// Verifies the caller owns the key before deleting it. Returns an error if the
/// caller tries to revoke a key they do not own. Revoking a non-existent key is
/// a no-op.
pub fn revoke_my_api_key(caller: Principal, hashed_key: &HashedApiKey) -> Result<(), String> {
    API_KEY_STATE.with_borrow_mut(|s| match s.api_keys.get(hashed_key) {
        Some(info) => {
            if info.principal != caller {
                Err("Unauthorized: You can only revoke your own API keys.".to_string())
            } else {
                s.api_keys.remove(hashed_key);
                Ok(())
            }
        }
        None => Ok(()),
    })
}

/// Look up the info for a hashed key (used by auth middleware to validate a key).
pub fn get_api_key_info(hashed_key: &HashedApiKey) -> Option<ApiKeyInfo> {
    API_KEY_STATE.with_borrow(|s| s.api_keys.get(hashed_key).cloned())
}

/// Hash a raw API key presented by a client, for lookup against the store.
pub fn hash_api_key(raw_key: &str) -> HashedApiKey {
    sha256_hex(raw_key.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(n: u8) -> Principal {
        Principal::from_slice(&[n; 29])
    }

    // Insert a key directly (bypassing raw_rand, which needs a canister).
    fn insert_key(caller: Principal, raw: &[u8], name: &str) -> HashedApiKey {
        let hashed = sha256_hex(raw);
        API_KEY_STATE.with_borrow_mut(|s| {
            s.api_keys.insert(
                hashed.clone(),
                ApiKeyInfo {
                    principal: caller,
                    scopes: vec!["read".to_string()],
                    name: name.to_string(),
                    created: 0,
                },
            );
        });
        hashed
    }

    #[test]
    fn list_returns_only_caller_keys() {
        let alice = principal(1);
        let bob = principal(2);
        let h1 = insert_key(alice, b"key-a", "alice-key");
        let _h2 = insert_key(bob, b"key-b", "bob-key");

        let alice_keys = list_my_api_keys(alice);
        assert_eq!(alice_keys.len(), 1);
        assert_eq!(alice_keys[0].hashed_key, h1);
        assert_eq!(alice_keys[0].info.name, "alice-key");

        // Bob must not see Alice's key.
        let bob_keys = list_my_api_keys(bob);
        assert!(bob_keys.iter().all(|k| k.info.principal == bob));
    }

    #[test]
    fn revoke_enforces_ownership() {
        let alice = principal(3);
        let bob = principal(4);
        let h = insert_key(alice, b"key-c", "alice-key");

        // Bob cannot revoke Alice's key.
        assert!(revoke_my_api_key(bob, &h).is_err());
        assert!(get_api_key_info(&h).is_some());

        // Alice can revoke her own key.
        assert!(revoke_my_api_key(alice, &h).is_ok());
        assert!(get_api_key_info(&h).is_none());
    }

    #[test]
    fn revoke_nonexistent_is_noop() {
        let alice = principal(5);
        assert!(revoke_my_api_key(alice, &"deadbeef".to_string()).is_ok());
    }

    #[test]
    fn hash_is_sha256_hex() {
        // SHA-256("") = e3b0c442...
        assert_eq!(
            hash_api_key(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
