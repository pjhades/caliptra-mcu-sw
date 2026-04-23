// Licensed under the Apache-2.0 license

use crate::spdm::cert_store::cert_chain::device::DeviceCertIndex;
use crate::spdm::cert_store::cert_chain::CertChain;
use crate::spdm::cert_store::DeviceCertStore;
use crate::spdm::endorsement_certs::EndorsementCertChain;
use caliptra_mcu_libapi_caliptra::crypto::asym::{AsymAlgo, ECC_P384_SIGNATURE_SIZE};
use caliptra_mcu_libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use caliptra_mcu_spdm_lib::cert_store::{CertStoreError, CertStoreResult, SpdmCertStore};
use caliptra_mcu_spdm_lib::protocol::{CertificateInfo, KeyUsageMask};
use core::mem::MaybeUninit;

/// Static storage just for the endorsement chain (since it needs static lifetime)
static mut SLOT0_ENDORSEMENT: MaybeUninit<EndorsementCertChain> = MaybeUninit::uninit();

/// Initialize the endorsement chain for a specific slot
fn init_endorsement_cert_chain(
    slot_id: u8,
) -> CertStoreResult<&'static mut EndorsementCertChain<'static>> {
    match slot_id {
        0 => {
            // Create the endorsement chain
            let endorsement_chain = EndorsementCertChain::new(0)?;
            unsafe {
                // Write the endorsement chain to static storage
                SLOT0_ENDORSEMENT.write(endorsement_chain);
                // Return the mutable reference with static lifetime
                Ok(SLOT0_ENDORSEMENT.assume_init_mut())
            }
        }
        _ => Err(CertStoreError::InvalidSlotId),
    }
}

pub fn initialize_cert_store() -> CertStoreResult<DeviceCertStore> {
    // Initialize the endorsement chain for slot 0 and get a static mutable reference
    let slot0_endorsement_ref = init_endorsement_cert_chain(0)?;

    // Create cert chain with the static reference
    let slot0_cert_chain = CertChain::new(slot0_endorsement_ref, DeviceCertIndex::IdevId);

    // Store everything in DeviceCertStore
    let mut cert_store = DeviceCertStore::new();
    cert_store.set_cert_chain(0, slot0_cert_chain)?;

    Ok(cert_store)
}

/// Wrapper that provides access to the global certificate store
/// This implements SpdmCertStore by forwarding calls to the global mutex-protected store
pub struct SharedCertStore {
    cert_store: DeviceCertStore,
}

impl SharedCertStore {
    pub fn new(cert_store: DeviceCertStore) -> Self {
        Self { cert_store }
    }
}

impl SpdmCertStore for SharedCertStore {
    fn slot_count(&self) -> u8 {
        self.cert_store.slot_count()
    }

    fn is_provisioned(&self, slot: u8) -> bool {
        self.cert_store.is_provisioned(slot)
    }

    fn cert_chain_len(&mut self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<usize> {
        self.cert_store.cert_chain_len(asym_algo, slot_id)
    }

    fn get_cert_chain<'a>(
        &mut self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        offset: usize,
        cert_portion: &'a mut [u8],
    ) -> CertStoreResult<usize> {
        self.cert_store
            .get_cert_chain(slot_id, asym_algo, offset, cert_portion)
    }

    fn root_cert_hash<'a>(
        &self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        self.cert_store
            .root_cert_hash(slot_id, asym_algo, cert_hash)
    }

    fn sign_hash<'a>(
        &self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        hash: &'a [u8; SHA384_HASH_SIZE],
        signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        self.cert_store
            .sign_hash(asym_algo, slot_id, hash, signature)
    }

    fn key_pair_id(&self, _slot_id: u8) -> Option<u8> {
        None
    }

    fn cert_info(&self, _slot_id: u8) -> Option<CertificateInfo> {
        None
    }

    fn key_usage_mask(&self, _slot_id: u8) -> Option<KeyUsageMask> {
        None
    }
}
