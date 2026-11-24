// SPDX-License-Identifier: EUPL-1.2

//! Remembered passwords of password profiles, in the user's keyring (Secret Service).
//!
//! Items are keyed by profile id and username. Nothing is stored unless the user asked for it
//! in the password dialog; a rejected login removes the stored password.

use cosmic_applet_fortivpn::profile::ProfileId;
use std::collections::HashMap;

/// Marks our items in the keyring.
const APPLICATION: &str = "io.github.snaggen.CosmicAppletFortivpn";

fn attributes<'a>(profile: &'a ProfileId, username: Option<&'a str>) -> HashMap<&'a str, &'a str> {
    let mut attributes =
        HashMap::from([("application", APPLICATION), ("profile", profile.as_str())]);
    if let Some(username) = username {
        attributes.insert("username", username);
    }
    attributes
}

/// The stored password of `username` for `profile`, if any. May show the keyring's unlock
/// prompt.
pub async fn load(profile: ProfileId, username: String) -> Result<Option<String>, String> {
    let keyring = oo7::Keyring::new().await.map_err(|err| err.to_string())?;
    keyring.unlock().await.map_err(|err| err.to_string())?;
    let items = keyring
        .search_items(&attributes(&profile, Some(&username)))
        .await
        .map_err(|err| err.to_string())?;
    let Some(item) = items.first() else {
        return Ok(None);
    };
    let secret = item.secret().await.map_err(|err| err.to_string())?;
    Ok(String::from_utf8(secret.to_vec()).ok())
}

/// Stores the password, replacing an earlier one for the same profile and username.
pub async fn store(
    profile: ProfileId,
    profile_name: String,
    username: String,
    password: String,
) -> Result<(), String> {
    let keyring = oo7::Keyring::new().await.map_err(|err| err.to_string())?;
    keyring.unlock().await.map_err(|err| err.to_string())?;
    let label = format!("OpenFortiVPN: {profile_name} ({username})");
    keyring
        .create_item(
            &label,
            &attributes(&profile, Some(&username)),
            password.as_str(),
            true,
        )
        .await
        .map_err(|err| err.to_string())
}

/// Removes every stored password of `profile`.
pub async fn forget(profile: ProfileId) -> Result<(), String> {
    let keyring = oo7::Keyring::new().await.map_err(|err| err.to_string())?;
    keyring
        .delete(&attributes(&profile, None))
        .await
        .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_name_profile_and_user() {
        let profile: ProfileId = "ace".parse().unwrap();
        let attrs = attributes(&profile, Some("anna"));
        assert_eq!(attrs.get("profile"), Some(&"ace"));
        assert_eq!(attrs.get("username"), Some(&"anna"));
        assert_eq!(attrs.get("application"), Some(&APPLICATION));
        assert!(!attributes(&profile, None).contains_key("username"));
    }
}
