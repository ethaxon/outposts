use std::collections::HashMap;

use reqwest::header::HeaderMap;

pub const SUBSCRIPTION_USERINFO_HEADER: &str = "subscription-userinfo";
pub const SUB_DOWNLOAD: &str = "download";
pub const SUB_UPLOAD: &str = "upload";
pub const SUB_TOTAL: &str = "total";
pub const SUB_EXPIRE: &str = "expire";

pub fn parse_subscription_userinfo(header_value: &str) -> HashMap<String, i64> {
    let mut fields = HashMap::new();

    for field in header_value.split(';') {
        let parts: Vec<&str> = field.trim().split('=').collect();
        if parts.len() == 2
            && let Ok(value) = parts[1].trim().parse::<i64>()
        {
            fields.insert(parts[0].trim().to_string(), value);
        }
    }

    fields
}

pub fn parse_subscription_userinfo_in_header(header: &HeaderMap) -> Option<HashMap<String, i64>> {
    let header_value = header.get(SUBSCRIPTION_USERINFO_HEADER)?;
    let header_str = header_value.to_str().ok()?;
    let mut fields = HashMap::new();

    for field in header_str.split(';') {
        let parts: Vec<&str> = field.trim().split('=').collect();
        if parts.len() == 2
            && let Ok(value) = parts[1].trim().parse::<i64>()
        {
            fields.insert(parts[0].trim().to_string(), value);
        }
    }

    Some(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_subscription_userinfo() {
        let header_value =
            "upload=5575992194; download=77012334; total=1234454555;expire=123444444";
        let fields = parse_subscription_userinfo(header_value);

        assert_eq!(fields.get("upload"), Some(&5575992194));
        assert_eq!(fields.get("download"), Some(&77012334));
        assert_eq!(fields.get("total"), Some(&1234454555));
        assert_eq!(fields.get("expire"), Some(&123444444));
    }

    #[test]
    fn test_parse_subscription_userinfo_invalid_value() {
        let header_value = "upload=5575992194; download=77012334; total=invalid; expire=123444444";
        let fields = parse_subscription_userinfo(header_value);

        assert_eq!(fields.get("upload"), Some(&5575992194));
        assert_eq!(fields.get("download"), Some(&77012334));
        assert_eq!(fields.get("total"), None);
        assert_eq!(fields.get("expire"), Some(&123444444));
    }

    #[test]
    fn test_parse_subscription_userinfo_missing_fields() {
        let header_value = "upload=5575992194; total=1234454555; expire=123444444";
        let fields = parse_subscription_userinfo(header_value);

        assert_eq!(fields.get("upload"), Some(&5575992194));
        assert_eq!(fields.get("download"), None);
        assert_eq!(fields.get("total"), Some(&1234454555));
        assert_eq!(fields.get("expire"), Some(&123444444));
    }
}
