use phantom_zone::{
    evaluator::NonInteractiveMultiPartyCrs,
    keys::{
        CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare,
        SeededNonInteractiveMultiPartyServerKey,
    },
    parameters::BoolParameters,
    SeededBatchedFheUint8,
};

pub type Seed = [u8; 32];
pub type ServerKeyShare = CommonReferenceSeededNonInteractiveMultiPartyServerKeyShare<
    Vec<Vec<u64>>,
    BoolParameters<u64>,
    NonInteractiveMultiPartyCrs<Seed>,
>;
pub type Cipher = SeededBatchedFheUint8<Vec<u64>, Seed>;
pub type DecryptionShare = Vec<u64>;
pub type ClientKey = phantom_zone::ClientKey;
pub type UserId = usize;
pub type EncryptedU8Values = SeededBatchedFheUint8<Vec<u64>, [u8; 32]>;
pub type ServerShare = SeededNonInteractiveMultiPartyServerKey<
    Vec<Vec<u64>>,
    NonInteractiveMultiPartyCrs<[u8; 32]>,
    BoolParameters<u64>,
>;

pub type FheUint8 = phantom_zone::FheUint8;
// A placeholder type alias for places that we would want to do
// FheUint8(0), ie encrypted constants or use plaintext values
pub type ConstFheUint8 = FheUint8;
