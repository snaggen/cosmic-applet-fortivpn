// SPDX-License-Identifier: EUPL-1.2

//! Translations: Fluent files under `i18n/<lang>/`, embedded at build time.
//! English is the fallback; the desktop's language settings pick the rest.

use i18n_embed::{
    DefaultLocalizer, LanguageLoader, Localizer,
    fluent::{FluentLanguageLoader, fluent_language_loader},
};
use rust_embed::RustEmbed;
use std::sync::LazyLock;

#[derive(RustEmbed)]
#[folder = "i18n/"]
struct Localizations;

pub static LANGUAGE_LOADER: LazyLock<FluentLanguageLoader> = LazyLock::new(|| {
    let loader: FluentLanguageLoader = fluent_language_loader!();
    // Deliberate startup failure: the English strings are embedded in the binary, so this only
    // fails if the build itself is broken, and the applet cannot show any text without them.
    #[allow(clippy::expect_used)]
    loader
        .load_fallback_language(&Localizations)
        .expect("embedded fallback language must load");
    loader
});

/// Looks up a translated message by id, with optional Fluent arguments.
#[macro_export]
macro_rules! fl {
    ($message_id:literal) => {{
        i18n_embed_fl::fl!($crate::localize::LANGUAGE_LOADER, $message_id)
    }};
    ($message_id:literal, $($args:expr),*) => {{
        i18n_embed_fl::fl!($crate::localize::LANGUAGE_LOADER, $message_id, $($args), *)
    }};
}

/// Selects the translation matching the desktop's requested languages.
///
/// Called once at startup, before the first string is shown.
pub fn localize() {
    let localizer = DefaultLocalizer::new(&*LANGUAGE_LOADER, &Localizations);
    let requested = i18n_embed::DesktopLanguageRequester::requested_languages();
    if let Err(err) = localizer.select(&requested) {
        tracing::warn!(%err, "could not load translations, using English");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Message ids defined in one embedded `.ftl` file.
    fn message_ids(path: &str) -> BTreeSet<String> {
        let file = Localizations::get(path).unwrap_or_else(|| panic!("{path} is not embedded"));
        let source = std::str::from_utf8(&file.data).expect("ftl files are UTF-8");
        source
            .lines()
            .filter_map(|line| line.split_once(" ="))
            .map(|(id, _)| id.trim())
            .filter(|id| id.starts_with(|c: char| c.is_ascii_lowercase()))
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn every_translation_has_the_same_messages_as_english() {
        let file_name = "cosmic_applet_fortivpn.ftl";
        let english = message_ids(&format!("en/{file_name}"));
        assert!(!english.is_empty());

        let languages: BTreeSet<String> = Localizations::iter()
            .filter_map(|path| path.split_once('/').map(|(lang, _)| lang.to_owned()))
            .filter(|lang| lang != "en")
            .collect();
        assert!(languages.contains("sv"));

        for lang in languages {
            let translated = message_ids(&format!("{lang}/{file_name}"));
            assert_eq!(translated, english, "messages in {lang} differ from en");
        }
    }

    #[test]
    fn swedish_is_selected_for_a_swedish_desktop() {
        let localizer = DefaultLocalizer::new(&*LANGUAGE_LOADER, &Localizations);
        let selected = localizer
            .select(&["sv-SE".parse().expect("valid language id")])
            .expect("Swedish loads");
        assert_eq!(
            selected.first().map(ToString::to_string).as_deref(),
            Some("sv")
        );
        assert_eq!(crate::fl!("status-disconnected"), "Frånkopplad");
    }
}
