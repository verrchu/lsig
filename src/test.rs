use super::{keypair, sign, verify};

#[test]
fn test() {
    let ((sk0, pk0), (sk1, pk1)) = (keypair(), keypair());

    let msg = b"test";

    let sig = sign(msg, (sk0, sk1));

    assert!(verify(msg, sig, (pk0, pk1)));
}
