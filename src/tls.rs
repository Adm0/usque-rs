use anyhow::{Context, Result};
use boring::asn1::Asn1Time;
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private};
use boring::ssl::{SslAlert, SslContextBuilder, SslMethod, SslVerifyError, SslVerifyMode};
use boring::x509::X509;

use crate::config::Config;
use crate::tunnel::TunnelConfig;

fn create_certificate(priv_key: &PKey<Private>) -> Result<X509> {
    let mut builder = X509::builder().map_err(|e| anyhow::anyhow!("x509 builder: {e}"))?;

    builder
        .set_not_before(Asn1Time::days_from_now(0)?.as_ref())
        .map_err(|e| anyhow::anyhow!("set not before: {e}"))?;

    builder
        .set_not_after(Asn1Time::days_from_now(1)?.as_ref())
        .map_err(|e| anyhow::anyhow!("set not after: {e}"))?;

    builder
        .set_pubkey(priv_key)
        .map_err(|e| anyhow::anyhow!("set pubkey: {e}"))?;

    builder
        .sign(priv_key, MessageDigest::sha256())
        .map_err(|e| anyhow::anyhow!("sign certificate: {e}"))?;

    Ok(builder.build())
}

pub fn prepare_quic_config(config: &Config, tunnel_cfg: &TunnelConfig) -> Result<quiche::Config> {
    let peer_pkey_der = config.get_endpoint_pub_key_der()?;
    let priv_key_der = config.get_ec_private_key_der()?;

    let peer_pub_key =
        PKey::public_key_from_der(&peer_pkey_der).context("failed to parse peer public key")?;

    let priv_key =
        PKey::private_key_from_der(&priv_key_der).context("failed to parse private key")?;

    let cert = create_certificate(&priv_key)?;

    let mut context = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| anyhow::anyhow!("ssl context: {e}"))?;

    if tunnel_cfg.disable_pq {
        context.set_curves_list("P-256:P-384:P-521")
    } else {
        context.set_curves_list("P256Kyber768Draft00:P-256:P-384:P-521")
    }
    .map_err(|e| anyhow::anyhow!("set curves list: {e}"))?;

    context.set_private_key(&priv_key)?;
    context.set_certificate(&cert)?;
    context.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        let Some(cert) = ssl.peer_certificate() else {
            return Err(SslVerifyError::Invalid(SslAlert::NO_CERTIFICATE));
        };

        let now = Asn1Time::days_from_now(0).unwrap();

        if cert.not_after().compare(&now).unwrap() == std::cmp::Ordering::Less {
            return Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_EXPIRED));
        }

        if cert.not_before().compare(&now).unwrap() == std::cmp::Ordering::Greater {
            return Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_EXPIRED));
        }

        let cert_pub_key = cert.public_key().unwrap();

        if !cert_pub_key.public_eq(peer_pub_key.as_ref()) {
            return Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE));
        }
        Ok(())
    });

    quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, context)
        .map_err(|e| anyhow::anyhow!("quiche config: {e}"))
}
