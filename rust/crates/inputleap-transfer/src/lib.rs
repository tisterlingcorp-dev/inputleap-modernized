#![forbid(unsafe_code)]
//! Fail-closed transfer queue used by the Rust migration boundary.

use inputleap_types::{DeviceId, DeviceRecord};
use std::collections::{HashMap, VecDeque};

pub const TRANSFER_PORT: u16 = 24_810;
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TransferId(u64);

impl TransferId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferRequest {
    pub id: TransferId,
    pub device: DeviceId,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferState {
    Queued,
    Sent,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferError {
    NotPaired,
    Revoked,
    EmptyPayload,
    OversizedPayload,
    UnknownTransfer,
    InvalidFrame,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferReceipt {
    pub id: TransferId,
    pub state: TransferState,
}

pub struct TransferQueue {
    next_id: u64,
    pending: VecDeque<TransferId>,
    requests: HashMap<TransferId, TransferRequest>,
    states: HashMap<TransferId, TransferState>,
}

impl Default for TransferQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferQueue {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            pending: VecDeque::new(),
            requests: HashMap::new(),
            states: HashMap::new(),
        }
    }

    pub fn enqueue(
        &mut self,
        device: &DeviceRecord,
        payload: Vec<u8>,
    ) -> Result<TransferReceipt, TransferError> {
        if !device.allows_transfer() {
            return Err(if device.trust == inputleap_types::DeviceTrust::Revoked {
                TransferError::Revoked
            } else {
                TransferError::NotPaired
            });
        }
        if payload.is_empty() {
            return Err(TransferError::EmptyPayload);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(TransferError::OversizedPayload);
        }
        let id = TransferId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(TransferError::UnknownTransfer)?;
        self.pending.push_back(id);
        self.requests.insert(
            id,
            TransferRequest {
                id,
                device: device.id,
                payload,
            },
        );
        self.states.insert(id, TransferState::Queued);
        Ok(TransferReceipt {
            id,
            state: TransferState::Queued,
        })
    }

    pub fn next_for(
        &mut self,
        device: &DeviceRecord,
    ) -> Result<Option<TransferRequest>, TransferError> {
        if !device.allows_transfer() {
            return Err(if device.trust == inputleap_types::DeviceTrust::Revoked {
                TransferError::Revoked
            } else {
                TransferError::NotPaired
            });
        }
        let Some(id) = self.pending.pop_front() else {
            return Ok(None);
        };
        let request = self
            .requests
            .get(&id)
            .cloned()
            .ok_or(TransferError::UnknownTransfer)?;
        if request.device != device.id {
            self.pending.push_back(id);
            return Ok(None);
        }
        self.states.insert(id, TransferState::Sent);
        Ok(Some(request))
    }

    pub fn cancel(&mut self, id: TransferId) -> Result<TransferReceipt, TransferError> {
        if !self.requests.contains_key(&id) {
            return Err(TransferError::UnknownTransfer);
        }
        self.pending.retain(|queued| *queued != id);
        self.states.insert(id, TransferState::Cancelled);
        Ok(TransferReceipt {
            id,
            state: TransferState::Cancelled,
        })
    }

    pub fn encode_frame(request: &TransferRequest) -> Result<Vec<u8>, TransferError> {
        if request.payload.is_empty() {
            return Err(TransferError::EmptyPayload);
        }
        if request.payload.len() > MAX_PAYLOAD {
            return Err(TransferError::OversizedPayload);
        }
        let frame_len = 8usize
            .checked_add(request.payload.len())
            .ok_or(TransferError::OversizedPayload)?;
        let mut frame = Vec::with_capacity(4 + frame_len);
        frame.extend_from_slice(&(frame_len as u32).to_be_bytes());
        frame.extend_from_slice(&request.id.0.to_be_bytes());
        frame.extend_from_slice(&request.payload);
        Ok(frame)
    }

    pub fn decode_frame(frame: &[u8]) -> Result<(TransferId, &[u8]), TransferError> {
        if frame.len() < 13 {
            return Err(TransferError::InvalidFrame);
        }
        let declared_len = u32::from_be_bytes(
            frame[..4]
                .try_into()
                .map_err(|_| TransferError::InvalidFrame)?,
        ) as usize;
        if !(9..=8 + MAX_PAYLOAD).contains(&declared_len) || declared_len + 4 != frame.len() {
            return Err(TransferError::InvalidFrame);
        }
        let id = u64::from_be_bytes(
            frame[4..12]
                .try_into()
                .map_err(|_| TransferError::InvalidFrame)?,
        );
        Ok((TransferId(id), &frame[12..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inputleap_types::DeviceTrust;

    fn paired(id: DeviceId) -> DeviceRecord {
        DeviceRecord {
            id,
            display_name: "peer".into(),
            trust: DeviceTrust::Paired,
        }
    }

    #[test]
    fn unpaired_and_revoked_devices_fail_closed() {
        let id = DeviceId::from_bytes([1; 16]);
        let mut queue = TransferQueue::new();
        let mut discovered = paired(id);
        discovered.trust = DeviceTrust::Discovered;
        assert_eq!(
            queue.enqueue(&discovered, vec![1]),
            Err(TransferError::NotPaired)
        );
        let mut revoked = paired(id);
        revoked.trust = DeviceTrust::Revoked;
        assert_eq!(
            queue.enqueue(&revoked, vec![1]),
            Err(TransferError::Revoked)
        );
    }

    #[test]
    fn queue_is_device_scoped_and_frame_is_length_prefixed() {
        let first = paired(DeviceId::from_bytes([1; 16]));
        let second = paired(DeviceId::from_bytes([2; 16]));
        let mut queue = TransferQueue::new();
        let receipt = queue.enqueue(&first, b"hello".to_vec()).unwrap();
        assert!(queue.next_for(&second).unwrap().is_none());
        let request = queue.next_for(&first).unwrap().unwrap();
        assert_eq!(request.id, receipt.id);
        assert_eq!(
            &TransferQueue::encode_frame(&request).unwrap()[..4],
            &13u32.to_be_bytes()
        );
    }

    #[test]
    fn malformed_payloads_are_rejected_without_queue_mutation() {
        let peer = paired(DeviceId::from_bytes([3; 16]));
        let mut queue = TransferQueue::new();
        assert_eq!(
            queue.enqueue(&peer, Vec::new()),
            Err(TransferError::EmptyPayload)
        );
        assert!(queue.next_for(&peer).unwrap().is_none());
    }

    #[test]
    fn decoder_rejects_truncated_or_mismatched_frames() {
        assert_eq!(
            TransferQueue::decode_frame(&[0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 1]),
            Err(TransferError::InvalidFrame)
        );
        assert_eq!(
            TransferQueue::decode_frame(&[0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 1, 1]),
            Err(TransferError::InvalidFrame)
        );
    }
}
