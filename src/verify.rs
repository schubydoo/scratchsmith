//! `verify`: check the keyless cosign signature on a registry image, and with `--sbom` its
//! SBOM attestation, against the identity and issuer the user names.

use crate::cli::UsageError;
use crate::registry::ManifestKind;
use crate::report::VerifyReport;
use crate::supplychain::{CertificateIdentity, SbomFormat};
use anyhow::{bail, Context, Result};

/// What `verify` checks.
#[derive(Debug)]
pub struct Request {
    /// The image reference as given, a tag or a digest.
    pub image: String,
    pub identity: CertificateIdentity,
    pub issuer: String,
    /// With `--sbom`: the attestation format to check.
    pub sbom: Option<SbomFormat>,
}

/// Run the checks in order and stop at the first that fails. Usage refusals come before
/// cosign or the registry is touched, except `--sbom` on an index, which needs the read.
pub fn run(req: &Request) -> Result<VerifyReport> {
    check_anchored(&req.identity)?;
    let reference = crate::registry::parse_image_reference(&req.image)?;
    crate::supplychain::check_cosign_to_verify()?;
    let resolved = crate::registry::resolve(&reference)?;
    if req.sbom.is_some() && resolved.kind == ManifestKind::Index {
        bail!(UsageError(format!(
            "{} is an image index. index --sign attaches no SBOM attestation, so --sbom does \
             not apply. Drop --sbom.",
            req.image
        )));
    }
    // cosign gets the digest read above, never the tag, so a tag that moves mid-run cannot
    // make the checked digest differ from the reported one.
    let image = &resolved.digest_ref;
    crate::supplychain::cosign_verify(image, &req.identity, &req.issuer)
        .with_context(|| format!("signature check failed for {image}"))?;
    let attestation = match req.sbom {
        Some(format) => {
            let kind = format.cosign_predicate_type();
            crate::supplychain::cosign_verify_attestation(image, kind, &req.identity, &req.issuer)
                .with_context(|| format!("attestation check failed for {image}"))?;
            Some(kind.to_string())
        }
        None => None,
    };
    Ok(VerifyReport {
        requested: req.image.clone(),
        image: resolved.digest_ref.clone(),
        kind: resolved.kind,
        identity: req.identity.value().to_string(),
        identity_is_regexp: matches!(req.identity, CertificateIdentity::Regexp(_)),
        issuer: req.issuer.clone(),
        signature: true,
        attestation,
        tag_digest: resolved.by_tag.then(|| resolved.digest.clone()),
    })
}

// cosign matches a pattern anywhere in the identity, so one with no leading `^` passes for a
// longer identity that contains it. Refused now, because a later release can relax the rule
// but not add it.
fn check_anchored(identity: &CertificateIdentity) -> Result<()> {
    match identity {
        CertificateIdentity::Regexp(pattern) if !pattern.starts_with('^') => {
            bail!(UsageError(format!(
                "the pattern {pattern} does not start with ^, so cosign matches it anywhere in \
                 the identity, and a longer identity that contains it passes too. Anchor it, \
                 for example: --certificate-identity-regexp '^{pattern}'"
            )))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unanchored_pattern_is_a_usage_refusal() {
        let err =
            check_anchored(&CertificateIdentity::Regexp("github\\.com/you/".into())).unwrap_err();
        assert!(crate::cli::is_usage(&err));
        assert!(
            err.to_string().contains("'^github\\.com/you/'"),
            "the message shows the anchored pattern: {err}"
        );
        check_anchored(&CertificateIdentity::Regexp("^github\\.com/you/".into())).unwrap();
        // An exact identity is not a pattern, so it needs no anchor.
        check_anchored(&CertificateIdentity::Exact("me@example.com".into())).unwrap();
    }
}
