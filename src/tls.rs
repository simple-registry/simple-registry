use log::{error, info};
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fmt::Display;
use std::io;
use std::path::Path;

pub fn load_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    info!("Loading private key from {}", path);
    let key = PrivateKeyDer::from_pem_file(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Error reading private key"))?;

    Ok(key)
}

pub fn load_certificate_bundle<T: AsRef<Path> + Display>(
    path: T,
) -> io::Result<Vec<CertificateDer<'static>>> {
    info!("Loading certificate bundle from {}", path);
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|err| {
            error!("Error opening certificate bundle: {:?}", err);
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Error opening certificate bundle",
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            error!("Error reading certificate bundle: {:?}", err);
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Error reading certificate bundle",
            )
        })?;

    Ok(certs)
}

pub fn build_root_store(certs: Vec<CertificateDer>) -> io::Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    for cert in certs {
        root_store.add(cert).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Failed to add CA certificate: {:?}", e),
            )
        })?;
    }
    Ok(root_store)
}
