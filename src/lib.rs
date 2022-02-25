#[cfg(test)]
mod test;

use bitvec::prelude::*;
use digest::Digest;
use rand::Rng;
use sha2::Sha256;

type Key = [[u8; 32]; 256];
type Keypair = (Key, Key);

fn keypair() -> Keypair {
    let mut rng = rand::thread_rng();

    let sk = [rng.gen::<[u8; 32]>(); 256];
    let pk = sk.map(Sha256::digest).map(Into::<[u8; 32]>::into);

    (sk, pk)
}

fn sign(msg: &[u8], (sk0, sk1): (Key, Key)) -> Key {
    let digest: [u8; 32] = Sha256::digest(msg).into();
    let bits = BitArray::<_, Lsb0>::new(digest);

    let mut signature = [[0; 32]; 256];

    for (i, bit) in bits.iter().enumerate() {
        match *bit {
            false => signature[i] = sk0[i],
            true => signature[i] = sk1[i],
        }
    }

    signature
}

fn verify(msg: &[u8], sig: Key, (pk0, pk1): (Key, Key)) -> bool {
    let digest: [u8; 32] = Sha256::digest(msg).into();
    let bits = BitArray::<_, Lsb0>::new(digest);

    for (i, bit) in bits.iter().enumerate() {
        let hash: [u8; 32] = Sha256::digest(sig[i]).into();

        match *bit {
            false => {
                if hash != pk0[i] {
                    return false;
                }
            }
            true => {
                if hash != pk1[i] {
                    return false;
                }
            }
        }
    }

    true
}
