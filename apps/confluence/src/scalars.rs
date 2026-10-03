use ts_rs::TS;

/// A named TypeScript scalar for DTO fields backed by database UUIDv7 identifiers.
#[derive(TS)]
#[ts(export, rename = "UUIDV7")]
pub struct UuidV7(pub uuid::Uuid);

/// A named TypeScript scalar for independently generated UUIDv4 subscription tokens.
#[derive(TS)]
#[ts(export, rename = "UUIDV4")]
pub struct UuidV4(pub uuid::Uuid);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuidv7_mapping_preserves_the_named_alias_and_automatic_import() {
        let config = ts_rs::Config::default();
        assert_eq!(UuidV7::decl(&config), "type UUIDV7 = string;");
        let profile = crate::dto::ProfileDto::export_to_string(&config).unwrap();
        assert!(profile.contains("import type { UUIDV7 }"));
        assert!(profile.contains("id: UUIDV7"));
        assert!(profile.contains("confluence_id: UUIDV7"));
        assert!(profile.contains("import type { UUIDV4 }"));
        assert!(profile.contains("resource_token: UUIDV4"));
        assert_eq!(UuidV4::decl(&config), "type UUIDV4 = string;");
    }
}
