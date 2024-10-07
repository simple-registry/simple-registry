use log::info;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::io;

pub fn load_private_key(path: &str) -> io::Result<PrivateKeyDer> {
    info!("Loading private key from {}", path);
    let key = PrivateKeyDer::from_pem_file(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Error reading private key"))?;

    Ok(key)
}

pub fn load_certificate_bundle(path: &str) -> io::Result<Vec<CertificateDer>> {
    info!("Loading certificate bundle from {}", path);
    let certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(path)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Error opening certificate bundle",
            )
        })?
        .collect::<Result<Vec<CertificateDer>, _>>()
        .map_err(|_| {
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
