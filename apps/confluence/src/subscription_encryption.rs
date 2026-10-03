use crate::error::AppError;
use std::io::Write;

pub(crate) fn encrypt_profile(yaml: &str, recipients: &[String]) -> Result<String, AppError> {
    if recipients.is_empty() {
        return Err(AppError::BadRequest {
            message: "ageRecipients must not be empty".into(),
        });
    }
    let recipients = recipients
        .iter()
        .map(|recipient| {
            recipient
                .parse::<age::x25519::Recipient>()
                .map_err(|_| AppError::BadRequest {
                    message: "invalid age X25519 recipient".into(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let encryptor = age::Encryptor::with_recipients(
        recipients
            .iter()
            .map(|recipient| recipient as &dyn age::Recipient),
    )
    .map_err(|_| AppError::internal_str("failed to initialize age encryption"))?;
    let armor = age::armor::ArmoredWriter::wrap_output(Vec::new(), age::armor::Format::AsciiArmor)
        .map_err(|_| AppError::internal_str("failed to initialize age armor"))?;
    let mut writer = encryptor
        .wrap_output(armor)
        .map_err(|_| AppError::internal_str("failed to initialize age writer"))?;
    writer
        .write_all(yaml.as_bytes())
        .map_err(|_| AppError::internal_str("failed to encrypt profile"))?;
    let output = writer
        .finish()
        .and_then(|armor| armor.finish())
        .map_err(|_| AppError::internal_str("failed to finish age profile"))?;
    String::from_utf8(output).map_err(|_| AppError::internal_str("invalid age armor encoding"))
}
