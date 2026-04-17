// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::transport::McuMboxTransport;
use alloc::boxed::Box;
use caliptra_api::mailbox::{CommandId as CaliptraCommandId, MailboxReqHeader};
use caliptra_mcu_external_cmds_common::{
    DeviceCapabilities, DeviceId, DeviceInfo, FirmwareVersion, UnifiedCommandHandler, MAX_UID_LEN,
};
use caliptra_mcu_libapi_caliptra::mailbox_api::execute_mailbox_cmd;
use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
use caliptra_mcu_libsyscall_caliptra::mcu_mbox::MbxCmdStatus;
use caliptra_mcu_mbox_common::messages::{
    CommandId, DeviceCapsReq, DeviceCapsResp, DeviceIdReq, DeviceIdResp, DeviceInfoReq,
    DeviceInfoResp, FirmwareVersionReq, FirmwareVersionResp, MailboxRespHeader,
    MailboxRespHeaderVarSize, McuAesDecryptInitReq, McuAesDecryptInitResp, McuAesDecryptUpdateReq,
    McuAesDecryptUpdateResp, McuAesEncryptInitReq, McuAesEncryptInitResp, McuAesEncryptUpdateReq,
    McuAesEncryptUpdateResp, McuAesGcmDecryptFinalReq, McuAesGcmDecryptFinalResp,
    McuAesGcmDecryptInitReq, McuAesGcmDecryptInitResp, McuAesGcmDecryptUpdateReq,
    McuAesGcmDecryptUpdateResp, McuAesGcmEncryptFinalReq, McuAesGcmEncryptFinalResp,
    McuAesGcmEncryptInitReq, McuAesGcmEncryptInitResp, McuAesGcmEncryptUpdateReq,
    McuAesGcmEncryptUpdateResp, McuCmDeleteReq, McuCmDeleteResp, McuCmImportReq, McuCmImportResp,
    McuCmStatusReq, McuCmStatusResp, McuEcdhFinishReq, McuEcdhFinishResp, McuEcdhGenerateReq,
    McuEcdhGenerateResp, McuEcdsaCmkPublicKeyReq, McuEcdsaCmkPublicKeyResp, McuEcdsaCmkSignReq,
    McuEcdsaCmkSignResp, McuEcdsaCmkVerifyReq, McuEcdsaCmkVerifyResp, McuFipsSelfTestGetResultsReq,
    McuFipsSelfTestGetResultsResp, McuFipsSelfTestStartReq, McuFipsSelfTestStartResp,
    McuHkdfExpandReq, McuHkdfExpandResp, McuHkdfExtractReq, McuHkdfExtractResp,
    McuHmacKdfCounterReq, McuHmacKdfCounterResp, McuHmacReq, McuHmacResp, McuMailboxResp,
    McuProdDebugUnlockReqReq, McuProdDebugUnlockReqResp, McuProdDebugUnlockTokenReq,
    McuProdDebugUnlockTokenResp, McuRandomGenerateReq, McuRandomGenerateResp, McuRandomStirReq,
    McuRandomStirResp, McuShaFinalReq, McuShaFinalResp, McuShaInitReq, McuShaInitResp,
    McuShaUpdateReq, DEVICE_CAPS_SIZE, MAX_FW_VERSION_STR_LEN,
};
#[cfg(feature = "periodic-fips-self-test")]
use caliptra_mcu_mbox_common::messages::{
    McuFipsPeriodicEnableReq, McuFipsPeriodicEnableResp, McuFipsPeriodicStatusReq,
    McuFipsPeriodicStatusResp,
};
use core::future::{ready, Future};
use core::mem::size_of;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug)]
pub enum MsgHandlerError {
    Transport,
    McuMboxCommon,
    NotReady,
    InvalidParams,
    UnsupportedCommand,
}

/// Command interface for handling MCU mailbox commands.
pub struct CmdInterface<'a> {
    transport: &'a mut McuMboxTransport,
    non_crypto_cmds_handler: &'a dyn UnifiedCommandHandler,
    caliptra_mbox: caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox, // Handle crypto commands via caliptra mailbox
    busy: AtomicBool,
}

impl<'a> CmdInterface<'a> {
    pub fn new(
        transport: &'a mut McuMboxTransport,
        non_crypto_cmds_handler: &'a dyn UnifiedCommandHandler,
    ) -> Self {
        Self {
            transport,
            non_crypto_cmds_handler,
            caliptra_mbox: Mailbox::new(),
            busy: AtomicBool::new(false),
        }
    }

    pub async fn handle_responder_msg(
        &mut self,
        msg_buf: &mut [u8],
    ) -> Result<(), MsgHandlerError> {
        // Receive a request from the transport.
        let receive_result = self.transport.receive_request(msg_buf).await;

        let status = match receive_result {
            Ok((cmd_id, req_len)) => {
                // Process the request and prepare the response.
                match self.process_request(msg_buf, cmd_id, req_len).await {
                    Ok((resp_len, status)) => {
                        if status == MbxCmdStatus::Complete {
                            self.transport
                                .send_response(&msg_buf[..resp_len])
                                .await
                                .map_err(|_| MsgHandlerError::Transport)?;
                        }
                        status
                    }
                    Err(_) => MbxCmdStatus::Failure,
                }
            }
            Err(_) => {
                // If the driver accepted the request but transport-level
                // validation failed, we still need to finalize. If no request
                // was received the finalize is harmlessly rejected.
                let _ = self.transport.finalize_response(MbxCmdStatus::Failure);
                return Err(MsgHandlerError::Transport);
            }
        };

        // Finalize the response as the last step of handling the message.
        self.transport
            .finalize_response(status)
            .map_err(|_| MsgHandlerError::Transport)?;

        Ok(())
    }

    async fn process_request(
        &mut self,
        msg_buf: &mut [u8],
        cmd: u32,
        req_len: usize,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        if self.busy.load(Ordering::SeqCst) {
            return Err(MsgHandlerError::NotReady);
        }

        self.busy.store(true, Ordering::SeqCst);

        let fut: Pin<Box<dyn Future<Output = Result<(usize, MbxCmdStatus), MsgHandlerError>>>> =
            match CommandId::from(cmd) {
                CommandId::MC_FIRMWARE_VERSION => Box::pin(self.handle_fw_version(msg_buf, req_len)),
                CommandId::MC_DEVICE_CAPABILITIES => {
                    Box::pin(self.handle_device_caps(msg_buf, req_len))
                }
                CommandId::MC_DEVICE_ID => Box::pin(self.handle_device_id(msg_buf, req_len)),
                CommandId::MC_DEVICE_INFO => Box::pin(self.handle_device_info(msg_buf, req_len)),
                CommandId::MC_FIPS_SELF_TEST_START => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuFipsSelfTestStartReq,
                        { size_of::<McuFipsSelfTestStartResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::SELF_TEST_START.into()),
                ),
                CommandId::MC_FIPS_SELF_TEST_GET_RESULTS => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuFipsSelfTestGetResultsReq,
                        { size_of::<McuFipsSelfTestGetResultsResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::SELF_TEST_GET_RESULTS.into()),
                ),
                #[cfg(feature = "periodic-fips-self-test")]
                CommandId::MC_FIPS_PERIODIC_ENABLE => {
                    Box::pin(ready(self.handle_fips_periodic_enable(msg_buf, req_len)))
                }
                #[cfg(feature = "periodic-fips-self-test")]
                CommandId::MC_FIPS_PERIODIC_STATUS => {
                    Box::pin(ready(self.handle_fips_periodic_status(msg_buf, req_len)))
                }
                CommandId::MC_SHA_INIT => Box::pin(
                    self.handle_crypto_passthrough::<McuShaInitReq, { size_of::<McuShaInitResp>() }>(
                        msg_buf,
                        req_len,
                        CaliptraCommandId::CM_SHA_INIT.into(),
                    ),
                ),
                CommandId::MC_SHA_UPDATE => Box::pin(
                    self.handle_crypto_passthrough::<McuShaUpdateReq, { size_of::<McuShaInitResp>() }>(
                        msg_buf,
                        req_len,
                        CaliptraCommandId::CM_SHA_UPDATE.into(),
                    ),
                ),
                CommandId::MC_SHA_FINAL => Box::pin(
                    self.handle_crypto_passthrough::<McuShaFinalReq, { size_of::<McuShaFinalResp>() }>(
                        msg_buf,
                        req_len,
                        CaliptraCommandId::CM_SHA_FINAL.into(),
                    ),
                ),
                CommandId::MC_HMAC => Box::pin(
                    self.handle_crypto_passthrough::<McuHmacReq, { size_of::<McuHmacResp>() }>(
                        msg_buf,
                        req_len,
                        CaliptraCommandId::CM_HMAC.into(),
                    ),
                ),
                CommandId::MC_HMAC_KDF_COUNTER => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuHmacKdfCounterReq,
                        { size_of::<McuHmacKdfCounterResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_HMAC_KDF_COUNTER.into()),
                ),
                CommandId::MC_HKDF_EXTRACT => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuHkdfExtractReq,
                        { size_of::<McuHkdfExtractResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_HKDF_EXTRACT.into()),
                ),
                CommandId::MC_HKDF_EXPAND => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuHkdfExpandReq,
                        { size_of::<McuHkdfExpandResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_HKDF_EXPAND.into()),
                ),
                CommandId::MC_IMPORT => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuCmImportReq,
                        { size_of::<McuCmImportResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_IMPORT.into()),
                ),
                CommandId::MC_DELETE => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuCmDeleteReq,
                        { size_of::<McuCmDeleteResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_DELETE.into()),
                ),
                CommandId::MC_CM_STATUS => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuCmStatusReq,
                        { size_of::<McuCmStatusResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_STATUS.into()),
                ),
                CommandId::MC_RANDOM_GENERATE => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuRandomGenerateReq,
                        { size_of::<McuRandomGenerateResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_RANDOM_GENERATE.into()),
                ),
                CommandId::MC_RANDOM_STIR => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuRandomStirReq,
                        { size_of::<McuRandomStirResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_RANDOM_STIR.into()),
                ),
                CommandId::MC_AES_ENCRYPT_INIT => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuAesEncryptInitReq,
                        { size_of::<McuAesEncryptInitResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_AES_ENCRYPT_INIT.into()),
                ),
                CommandId::MC_AES_ENCRYPT_UPDATE => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuAesEncryptUpdateReq,
                        { size_of::<McuAesEncryptUpdateResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_AES_ENCRYPT_UPDATE.into()),
                ),
                CommandId::MC_AES_DECRYPT_INIT => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuAesDecryptInitReq,
                        { size_of::<McuAesDecryptInitResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_AES_DECRYPT_INIT.into()),
                ),
                CommandId::MC_AES_DECRYPT_UPDATE => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuAesDecryptUpdateReq,
                        { size_of::<McuAesDecryptUpdateResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_AES_DECRYPT_UPDATE.into()),
                ),
                CommandId::MC_AES_GCM_ENCRYPT_INIT => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuAesGcmEncryptInitReq,
                        { size_of::<McuAesGcmEncryptInitResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_AES_GCM_ENCRYPT_INIT.into()),
                ),
                CommandId::MC_AES_GCM_ENCRYPT_UPDATE => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuAesGcmEncryptUpdateReq,
                        { size_of::<McuAesGcmEncryptUpdateResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_AES_GCM_ENCRYPT_UPDATE.into()),
                ),
                CommandId::MC_AES_GCM_ENCRYPT_FINAL => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuAesGcmEncryptFinalReq,
                        { size_of::<McuAesGcmEncryptFinalResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_AES_GCM_ENCRYPT_FINAL.into()),
                ),
                CommandId::MC_AES_GCM_DECRYPT_INIT => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuAesGcmDecryptInitReq,
                        { size_of::<McuAesGcmDecryptInitResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_AES_GCM_DECRYPT_INIT.into()),
                ),
                CommandId::MC_AES_GCM_DECRYPT_UPDATE => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuAesGcmDecryptUpdateReq,
                        { size_of::<McuAesGcmDecryptUpdateResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_AES_GCM_DECRYPT_UPDATE.into()),
                ),
                CommandId::MC_AES_GCM_DECRYPT_FINAL => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuAesGcmDecryptFinalReq,
                        { size_of::<McuAesGcmDecryptFinalResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_AES_GCM_DECRYPT_FINAL.into()),
                ),
                CommandId::MC_ECDH_GENERATE => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuEcdhGenerateReq,
                        { size_of::<McuEcdhGenerateResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_ECDH_GENERATE.into()),
                ),
                CommandId::MC_ECDH_FINISH => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuEcdhFinishReq,
                        { size_of::<McuEcdhFinishResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_ECDH_FINISH.into()),
                ),
                CommandId::MC_ECDSA_CMK_PUBLIC_KEY => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuEcdsaCmkPublicKeyReq,
                        { size_of::<McuEcdsaCmkPublicKeyResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_ECDSA_PUBLIC_KEY.into()),
                ),
                CommandId::MC_ECDSA_CMK_SIGN => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuEcdsaCmkSignReq,
                        { size_of::<McuEcdsaCmkSignResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_ECDSA_SIGN.into()),
                ),
                CommandId::MC_ECDSA_CMK_VERIFY => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuEcdsaCmkVerifyReq,
                        { size_of::<McuEcdsaCmkVerifyResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::CM_ECDSA_VERIFY.into()),
                ),
                CommandId::MC_PROD_DEBUG_UNLOCK_REQ => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuProdDebugUnlockReqReq,
                        { size_of::<McuProdDebugUnlockReqResp>() },
                    >(msg_buf, req_len, CaliptraCommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ.into()),
                ),
                CommandId::MC_PROD_DEBUG_UNLOCK_TOKEN => Box::pin(
                    self.handle_crypto_passthrough::<
                        McuProdDebugUnlockTokenReq,
                        { size_of::<McuProdDebugUnlockTokenResp>() },
                    >(
                        msg_buf,
                        req_len,
                        CaliptraCommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.into(),
                    ),
                ),
                // TODO: add more command handlers.
                // TODO: DOT runtime commands (DOT_CAK_INSTALL, DOT_LOCK, DOT_DISABLE,
                // DOT_UNLOCK_CHALLENGE, DOT_UNLOCK) are not yet handled here. These require
                // Ownership_Storage support and CommandId definitions to be added first.
                _ => Box::pin(ready(Err(MsgHandlerError::UnsupportedCommand))),
            };

        let result = fut.await;
        self.busy.store(false, Ordering::SeqCst);
        result
    }

    async fn handle_fw_version(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        // Decode the request
        let req: &FirmwareVersionReq = FirmwareVersionReq::ref_from_bytes(&msg_buf[..req_len])
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        let index = req.index;
        let mut version = FirmwareVersion::default();

        let ret = self
            .non_crypto_cmds_handler
            .get_firmware_version(index, &mut version)
            .await;

        let mbox_cmd_status = if ret.is_ok() && version.len <= MAX_FW_VERSION_STR_LEN {
            MbxCmdStatus::Complete
        } else {
            MbxCmdStatus::Failure
        };

        let mut resp = if mbox_cmd_status == MbxCmdStatus::Complete {
            McuMailboxResp::FirmwareVersion(FirmwareVersionResp {
                hdr: MailboxRespHeaderVarSize {
                    data_len: version.len as u32,
                    ..Default::default()
                },
                version: version.ver_str,
            })
        } else {
            McuMailboxResp::FirmwareVersion(FirmwareVersionResp::default())
        };

        // Populate the checksum for response
        resp.populate_chksum()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        // Encode the response and copy to msg_buf.
        let resp_bytes = resp
            .as_bytes()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        msg_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((resp_bytes.len(), mbox_cmd_status))
    }

    async fn handle_device_caps(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        let _req = DeviceCapsReq::ref_from_bytes(&msg_buf[..req_len])
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        // Prepare response
        let mut caps = DeviceCapabilities::default();
        let ret = self
            .non_crypto_cmds_handler
            .get_device_capabilities(&mut caps)
            .await;

        let mbox_cmd_status = if ret.is_ok() && caps.as_bytes().len() <= DEVICE_CAPS_SIZE {
            MbxCmdStatus::Complete
        } else {
            MbxCmdStatus::Failure
        };

        let mut resp = if mbox_cmd_status == MbxCmdStatus::Complete {
            let mut c = [0u8; DEVICE_CAPS_SIZE];
            c[..caps.as_bytes().len()].copy_from_slice(caps.as_bytes());
            McuMailboxResp::DeviceCaps(DeviceCapsResp {
                hdr: MailboxRespHeader::default(),
                caps: c,
            })
        } else {
            McuMailboxResp::DeviceCaps(DeviceCapsResp::default())
        };

        // Populate the checksum for response
        resp.populate_chksum()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        // Encode the response and copy to msg_buf.
        let resp_bytes = resp
            .as_bytes()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        msg_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((resp_bytes.len(), mbox_cmd_status))
    }

    async fn handle_device_id(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        let _req = DeviceIdReq::ref_from_bytes(&msg_buf[..req_len])
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        // Prepare response
        let mut device_id = DeviceId::default();
        let ret = self
            .non_crypto_cmds_handler
            .get_device_id(&mut device_id)
            .await;

        let mbox_cmd_status = if ret.is_ok() {
            MbxCmdStatus::Complete
        } else {
            MbxCmdStatus::Failure
        };

        let mut resp = McuMailboxResp::DeviceId(DeviceIdResp {
            hdr: MailboxRespHeader::default(),
            vendor_id: device_id.vendor_id,
            device_id: device_id.device_id,
            subsystem_vendor_id: device_id.subsystem_vendor_id,
            subsystem_id: device_id.subsystem_id,
        });

        // Populate the checksum for response
        resp.populate_chksum()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        // Encode the response and copy to msg_buf.
        let resp_bytes = resp
            .as_bytes()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        msg_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((resp_bytes.len(), mbox_cmd_status))
    }

    async fn handle_device_info(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        // Decode the request
        let req = DeviceInfoReq::ref_from_bytes(&msg_buf[..req_len])
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        // Prepare response
        let mut device_info = DeviceInfo::Uid(Default::default());
        let ret = self
            .non_crypto_cmds_handler
            .get_device_info(req.index, &mut device_info)
            .await;

        let mbox_cmd_status = if ret.is_ok() {
            MbxCmdStatus::Complete
        } else {
            MbxCmdStatus::Failure
        };

        let mut resp = if mbox_cmd_status == MbxCmdStatus::Complete {
            let DeviceInfo::Uid(uid) = &device_info;
            let mut data = [0u8; MAX_UID_LEN];
            data[..uid.len].copy_from_slice(&uid.unique_chip_id[..uid.len]);
            McuMailboxResp::DeviceInfo(DeviceInfoResp {
                hdr: MailboxRespHeaderVarSize {
                    data_len: uid.len as u32,
                    ..Default::default()
                },
                data,
            })
        } else {
            McuMailboxResp::DeviceInfo(DeviceInfoResp::default())
        };

        // Populate the checksum for response
        resp.populate_chksum()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        // Encode the response and copy to msg_buf.
        let resp_bytes = resp
            .as_bytes()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        msg_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((resp_bytes.len(), mbox_cmd_status))
    }

    pub async fn handle_crypto_passthrough<T: Default + IntoBytes + FromBytes, const N: usize>(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
        caliptra_cmd_code: u32,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        if req_len > size_of::<T>() {
            return Err(MsgHandlerError::InvalidParams);
        }
        let mut req = T::default();
        req.as_mut_bytes()[..req_len].copy_from_slice(&msg_buf[..req_len]);

        // Clear the header checksum field because it was computed for the MCU mailbox CmdID and payload.
        req.as_mut_bytes()[..size_of::<MailboxReqHeader>()].fill(0);

        let mut resp_buf = [0u8; N];

        // Invoke Caliptra mailbox API
        let status = execute_mailbox_cmd(
            &self.caliptra_mbox,
            caliptra_cmd_code,
            req.as_mut_bytes(),
            &mut resp_buf,
        )
        .await;

        match status {
            Ok(resp_len) => {
                msg_buf[..resp_len].copy_from_slice(&resp_buf[..resp_len]);
                Ok((resp_len, MbxCmdStatus::Complete))
            }
            Err(_) => Ok((0, MbxCmdStatus::Failure)),
        }
    }

    #[cfg(feature = "periodic-fips-self-test")]
    fn handle_fips_periodic_enable(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        use crate::fips_periodic;

        // Parse the request
        let req = McuFipsPeriodicEnableReq::ref_from_bytes(&msg_buf[..req_len])
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        // Enable or disable based on request
        fips_periodic::set_enabled(req.enable != 0);

        // Prepare response
        let mut resp = McuMailboxResp::FipsPeriodicEnable(McuFipsPeriodicEnableResp(
            MailboxRespHeader::default(),
        ));

        // Populate the checksum for response
        resp.populate_chksum()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        // Encode the response and copy to msg_buf
        let resp_bytes = resp
            .as_bytes()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        msg_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((resp_bytes.len(), MbxCmdStatus::Complete))
    }

    #[cfg(feature = "periodic-fips-self-test")]
    fn handle_fips_periodic_status(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        use crate::fips_periodic;

        // Parse the request (just header, no additional data)
        let _req = McuFipsPeriodicStatusReq::ref_from_bytes(&msg_buf[..req_len])
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        // Get status
        let (enabled, iterations, last_result) = fips_periodic::get_status();

        // Prepare response
        let mut resp = McuMailboxResp::FipsPeriodicStatus(McuFipsPeriodicStatusResp {
            header: MailboxRespHeader::default(),
            enabled: if enabled { 1 } else { 0 },
            iterations,
            last_result,
        });

        // Populate the checksum for response
        resp.populate_chksum()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        // Encode the response and copy to msg_buf
        let resp_bytes = resp
            .as_bytes()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        msg_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((resp_bytes.len(), MbxCmdStatus::Complete))
    }
}
