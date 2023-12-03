// Implementation of CMZ14 credentials (GGM version, which is more
// efficient, but makes a stronger security assumption): "Algebraic MACs
// and Keyed-Verification Anonymous Credentials" (Chase, Meiklejohn,
// and Zaverucha, CCS 2014)

// The notation follows that of the paper "Hyphae: Social Secret
// Sharing" (Lovecruft and de Valence, 2017), Section 4.

// We really want points to be capital letters and scalars to be
// lowercase letters
#![allow(non_snake_case)]

use serde::Serialize;
use serde::Deserialize;
use sha2::Sha512;

use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use lazy_static::lazy_static;


lazy_static! {
    pub static ref CMZ_A: RistrettoPoint =
        RistrettoPoint::hash_from_bytes::<Sha512>(b"CMZ Generator A");
    pub static ref CMZ_B: RistrettoPoint = dalek_constants::RISTRETTO_BASEPOINT_POINT;
    pub static ref CMZ_A_TABLE: RistrettoBasepointTable = RistrettoBasepointTable::create(&CMZ_A);
    pub static ref CMZ_B_TABLE: RistrettoBasepointTable =
        dalek_constants::RISTRETTO_BASEPOINT_TABLE;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerPrivKey {
    x0tilde: Scalar,
    x: Vec<Scalar>,
}

impl IssuerPrivKey {
    // Create an IssuerPrivKey for credentials with the given number of
    // attributes.
    pub fn new(n: u16) -> IssuerPrivKey {
        let mut rng = rand::thread_rng();
        let x0tilde = Scalar::random(&mut rng);
        let mut x: Vec<Scalar> = Vec::with_capacity((n + 1) as usize);

        // Set x to a vector of n+1 random Scalars
        x.resize_with((n + 1) as usize, || Scalar::random(&mut rng));

        IssuerPrivKey { x0tilde, x }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerPubKey {
    X: Vec<RistrettoPoint>,
}

impl IssuerPubKey {
    // Create an IssuerPubKey from the corresponding IssuerPrivKey
    pub fn new(privkey: &IssuerPrivKey) -> IssuerPubKey {
        let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;
        let Btable: &RistrettoBasepointTable = &CMZ_B_TABLE;
        let n_plus_one = privkey.x.len();
        let mut X: Vec<RistrettoPoint> = Vec::with_capacity(n_plus_one);

        // The first element is a special case; it is
        // X[0] = x0tilde*A + x[0]*B
        X.push(&privkey.x0tilde * Atable + &privkey.x[0] * Btable);

        // The other elements (1 through n) are X[i] = x[i]*A
        for i in 1..n_plus_one {
            X.push(&privkey.x[i] * Atable);
        }
        IssuerPubKey { X }
    }
}

#[derive(Clone, Debug)]
pub struct Issuer {
    privkey: IssuerPrivKey,
    pub pubkey: IssuerPubKey,
}

impl Issuer {
    // Create an issuer for credentials with the given number of
    // attributes
    pub fn new(n: u16) -> Issuer {
        let privkey = IssuerPrivKey::new(n);
        let pubkey = IssuerPubKey::new(&privkey);
        Issuer { privkey, pubkey }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Credential {
    P: RistrettoPoint,
    Q: RistrettoPoint,
    // For numbering consistency with the Hyphae paper, the attributes
    // are stored in m[1], m[2], ... ; the m[0] element is set to the
    // dummy value 0.
    pub m: Vec<Scalar>,
}

// A submodule for issuing credentials with 5 attributes, none of which
// are blinded to the issuer.  We create these submodules because the
// zero knowledge proofs (ZKPs) have to have the number of attributes
// hardcoded.  One might imagine a Rust macro that could generate
// submodules like these automatically, but for now, if you need a
// different number of attributes, or different combinations of blinded
// attributes, it is hopefully straighforward to adapt these given ones.
// Note that the "nonblind" issuing case is special: the client doesn't
// do a ZKP at all.  The more general blinded issuing case is the next
// submodule after this one.
pub mod issue_nonblind_5 {
    use curve25519_dalek::ristretto::RistrettoBasepointTable;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::IsIdentity;

    use zkp::CompactProof;
    use zkp::ProofError;
    use zkp::Transcript;
    use serde::Serialize;
    use serde::Deserialize;

    use super::{Credential, Issuer, IssuerPubKey, CMZ_A, CMZ_B, CMZ_B_TABLE};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct CredentialRequest {
        m1: Scalar,
        m2: Scalar,
        m3: Scalar,
        m4: Scalar,
        m5: Scalar,
    }

    #[derive(Clone, Copy, Debug)]
    pub struct CredentialRequestState {
        m1: Scalar,
        m2: Scalar,
        m3: Scalar,
        m4: Scalar,
        m5: Scalar,
    }

    #[derive(Serialize, Deserialize)]
    pub struct CredentialResponse {
        P: RistrettoPoint,
        Q: RistrettoPoint,
        piNonblindIssue: CompactProof,
    }

    define_proof! {
        issue,
        "Nonblind 5 issuing proof",
        (x0, x0tilde, x1, x2, x3, x4, x5),
        (P, Q, X0, X1, X2, X3, X4, X5, P1, P2, P3, P4, P5),
        (A, B) :
        X1 = (x1*A),
        X2 = (x2*A),
        X3 = (x3*A),
        X4 = (x4*A),
        X5 = (x5*A),
        X0 = (x0*B + x0tilde*A),
        Q = (x0*P + x1*P1 + x2*P2 + x3*P3 + x4*P4 + x5*P5)
    }

    pub fn request(
        m1: &Scalar,
        m2: &Scalar,
        m3: &Scalar,
        m4: &Scalar,
        m5: &Scalar,
    ) -> (CredentialRequest, CredentialRequestState) {
        // For nonblind requests, just send the attributes in the clear
        (
            CredentialRequest {
                m1: *m1,
                m2: *m2,
                m3: *m3,
                m4: *m4,
                m5: *m5,
            },
            CredentialRequestState {
                m1: *m1,
                m2: *m2,
                m3: *m3,
                m4: *m4,
                m5: *m5,
            },
        )
    }

    impl Issuer {
        // Issue a credential with (for example) 5 given attributes.  In
        // this (nonblinded) version, the issuer sees all of the attributes.
        pub fn issue_nonblind_5(&self, req: CredentialRequest) -> CredentialResponse {
            let A: &RistrettoPoint = &CMZ_A;
            let B: &RistrettoPoint = &CMZ_B;
            let Btable: &RistrettoBasepointTable = &CMZ_B_TABLE;

            let mut rng = rand::thread_rng();
            let b = Scalar::random(&mut rng);
            let P = &b * Btable;
            // There is a typo in the Hyphae paper: in Section 4.1, Q should
            // also have an x0*P term (also in Q').  (You can see that term
            // in Section 4.2.)
            let Q = (self.privkey.x[0]
                + (self.privkey.x[1] * req.m1
                    + self.privkey.x[2] * req.m2
                    + self.privkey.x[3] * req.m3
                    + self.privkey.x[4] * req.m4
                    + self.privkey.x[5] * req.m5))
                * P;

            let mut transcript = Transcript::new(b"Nonblind 5 issuing proof");
            let piNonblindIssue = issue::prove_compact(
                &mut transcript,
                issue::ProveAssignments {
                    A: &A,
                    B: &B,
                    P: &P,
                    Q: &Q,
                    X0: &self.pubkey.X[0],
                    X1: &self.pubkey.X[1],
                    X2: &self.pubkey.X[2],
                    X3: &self.pubkey.X[3],
                    X4: &self.pubkey.X[4],
                    X5: &self.pubkey.X[5],
                    P1: &(req.m1 * P),
                    P2: &(req.m2 * P),
                    P3: &(req.m3 * P),
                    P4: &(req.m4 * P),
                    P5: &(req.m5 * P),
                    x0: &self.privkey.x[0],
                    x1: &self.privkey.x[1],
                    x2: &self.privkey.x[2],
                    x3: &self.privkey.x[3],
                    x4: &self.privkey.x[4],
                    x5: &self.privkey.x[5],
                    x0tilde: &self.privkey.x0tilde,
                },
            )
            .0;

            CredentialResponse {
                P,
                Q,
                piNonblindIssue,
            }
        }
    }

    pub fn verify(
        state: CredentialRequestState,
        resp: CredentialResponse,
        pubkey: &IssuerPubKey,
    ) -> Result<Credential, ProofError> {
        let A: &RistrettoPoint = &CMZ_A;
        let B: &RistrettoPoint = &CMZ_B;

        if resp.P.is_identity() {
            return Err(ProofError::VerificationFailure);
        }
        let mut transcript = Transcript::new(b"Nonblind 5 issuing proof");
        issue::verify_compact(
            &resp.piNonblindIssue,
            &mut transcript,
            issue::VerifyAssignments {
                A: &A.compress(),
                B: &B.compress(),
                P: &resp.P.compress(),
                Q: &resp.Q.compress(),
                X0: &pubkey.X[0].compress(),
                X1: &pubkey.X[1].compress(),
                X2: &pubkey.X[2].compress(),
                X3: &pubkey.X[3].compress(),
                X4: &pubkey.X[4].compress(),
                X5: &pubkey.X[5].compress(),
                P1: &(state.m1 * resp.P).compress(),
                P2: &(state.m2 * resp.P).compress(),
                P3: &(state.m3 * resp.P).compress(),
                P4: &(state.m4 * resp.P).compress(),
                P5: &(state.m5 * resp.P).compress(),
            },
        )?;
        Ok(Credential {
            P: resp.P,
            Q: resp.Q,
            m: vec![
                Scalar::zero(),
                state.m1,
                state.m2,
                state.m3,
                state.m4,
                state.m5,
            ],
        })
    }
}

// A submodule for issuing credentials with 5 attributes, of which
// attributes 1, 2, and 4 are blinded (the issuer does not see them),
// and only attributes 3 and 5 are visible to the issuer.
//
// One might imagine generalizing this submodule using a macro.
// Currently, the number of attributes and the selection of which are
// blinded have to be hardcoded in order to use the very helpful zkp
// proof macros.  This shouldn't be a problem in practice, as one
// generally knows the set of statements one will require at compile,
// and not at run, time.
pub mod issue_blind124_5 {
    use curve25519_dalek::ristretto::RistrettoBasepointTable;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::IsIdentity;

    use zkp::CompactProof;
    use zkp::ProofError;
    use zkp::Transcript;
    use serde::Serialize;
    use serde::Deserialize;

    use super::{Credential, Issuer, IssuerPubKey};
    use super::{CMZ_A, CMZ_A_TABLE, CMZ_B, CMZ_B_TABLE};

    // Example of a 5-attribute credential where the issuer sees attributes
    // 3 and 5, but attributes 1, 2, and 4 are blinded.
    #[derive(Serialize, Deserialize)]
    pub struct CredentialRequest {
        D: RistrettoPoint,
        Encm1B: (RistrettoPoint, RistrettoPoint),
        Encm2B: (RistrettoPoint, RistrettoPoint),
        m3: Scalar,
        Encm4B: (RistrettoPoint, RistrettoPoint),
        m5: Scalar,
        piUserBlinding: CompactProof,
    }

    #[derive(Clone, Copy, Debug, Serialize, Deserialize)]
    pub struct CredentialRequestState {
        d: Scalar,
        D: RistrettoPoint,
        Encm1B: (RistrettoPoint, RistrettoPoint),
        Encm2B: (RistrettoPoint, RistrettoPoint),
        Encm4B: (RistrettoPoint, RistrettoPoint),
        m1: Scalar,
        m2: Scalar,
        m3: Scalar,
        m4: Scalar,
        m5: Scalar,
    }

    #[derive(Serialize, Deserialize)]
    pub struct CredentialResponse {
        P: RistrettoPoint,
        EncQ: (RistrettoPoint, RistrettoPoint),
        T1: RistrettoPoint,
        T2: RistrettoPoint,
        T4: RistrettoPoint,
        piBlindIssue: CompactProof,
    }

    // The client-created proof that the blinded attributes in the request
    // to issue a credential are well formed.  If you want the client to
    // prove other statements about the blinded attributes (m1, m2, m4 in
    // this example), this is where to add them (and in the code that
    // creates and verifies this proof of course).
    define_proof! {
        userblinding,
        "Blind124 5 userblind proof",
        (d, e1, e2, e4, m1, m2, m4),
        (Encm1B0, Encm1B1, Encm2B0, Encm2B1, Encm4B0, Encm4B1, D),
        (B) :
        Encm1B0 = (e1*B),
        Encm1B1 = (m1*B + e1*D),
        Encm2B0 = (e2*B),
        Encm2B1 = (m2*B + e2*D),
        Encm4B0 = (e4*B),
        Encm4B1 = (m4*B + e4*D),
        D = (d*B)
    }

    // The issuer-created proof for the same scenario
    define_proof! {
        blindissue,
        "Blind124 5 issuing proof",
        (x0, x0tilde, x1, x2, x3, x4, x5, s, b, t1, t2, t4),
        (P, EncQ0, EncQ1, X0, X1, X2, X3, X4, X5, P3, P5, T1, T2, T4, D,
            Encm1B0, Encm1B1, Encm2B0, Encm2B1, Encm4B0, Encm4B1),
        (A, B) :
        X1 = (x1*A),
        X2 = (x2*A),
        X3 = (x3*A),
        X4 = (x4*A),
        X5 = (x5*A),
        X0 = (x0*B + x0tilde*A),
        P = (b*B),
        T1 = (b*X1),
        T2 = (b*X2),
        T4 = (b*X4),
        T1 = (t1*A),
        T2 = (t2*A),
        T4 = (t4*A),
        EncQ0 = (s*B + t1*Encm1B0 + t2*Encm2B0 + t4*Encm4B0),
        EncQ1 = (s*D + t1*Encm1B1 + t2*Encm2B1 + t4*Encm4B1 +
                x0*P + x3*P3 + x5*P5)
    }

    pub fn request(
        m1: &Scalar,
        m2: &Scalar,
        m3: &Scalar,
        m4: &Scalar,
        m5: &Scalar,
    ) -> (CredentialRequest, CredentialRequestState) {
        let B: &RistrettoPoint = &CMZ_B;
        let Btable: &RistrettoBasepointTable = &CMZ_B_TABLE;

        // Pick an ElGamal keypair
        let mut rng = rand::thread_rng();
        let d = Scalar::random(&mut rng);
        let D = &d * Btable;

        // Encrypt the attributes to be blinded (each times the
        // basepoint B) to the public key we just created
        let e1 = Scalar::random(&mut rng);
        let e2 = Scalar::random(&mut rng);
        let e4 = Scalar::random(&mut rng);
        let Encm1B = (&e1 * Btable, m1 * Btable + e1 * D);
        let Encm2B = (&e2 * Btable, m2 * Btable + e2 * D);
        let Encm4B = (&e4 * Btable, m4 * Btable + e4 * D);

        let mut transcript = Transcript::new(b"Blind124 5 userblind proof");
        let piUserBlinding = userblinding::prove_compact(
            &mut transcript,
            userblinding::ProveAssignments {
                B: &B,
                Encm1B0: &Encm1B.0,
                Encm1B1: &Encm1B.1,
                Encm2B0: &Encm2B.0,
                Encm2B1: &Encm2B.1,
                Encm4B0: &Encm4B.0,
                Encm4B1: &Encm4B.1,
                D: &D,
                d: &d,
                e1: &e1,
                e2: &e2,
                e4: &e4,
                m1: &m1,
                m2: &m2,
                m4: &m4,
            },
        )
        .0;
        (
            CredentialRequest {
                D,
                Encm1B,
                Encm2B,
                Encm4B,
                piUserBlinding,
                m3: *m3,
                m5: *m5,
            },
            CredentialRequestState {
                d,
                D,
                Encm1B,
                Encm2B,
                Encm4B,
                m1: *m1,
                m2: *m2,
                m3: *m3,
                m4: *m4,
                m5: *m5,
            },
        )
    }

    impl Issuer {
        // Issue a credential with 5 attributes, of which attributes 1, 2,
        // and 4 are blinded from the issuer, and 3 and 5 are visible.
        pub fn issue_blind124_5(
            &self,
            req: CredentialRequest,
        ) -> Result<CredentialResponse, ProofError> {
            let A: &RistrettoPoint = &CMZ_A;
            let B: &RistrettoPoint = &CMZ_B;
            let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;
            let Btable: &RistrettoBasepointTable = &CMZ_B_TABLE;

            // First check the proof in the request
            let mut transcript = Transcript::new(b"Blind124 5 userblind proof");
            userblinding::verify_compact(
                &req.piUserBlinding,
                &mut transcript,
                userblinding::VerifyAssignments {
                    B: &B.compress(),
                    Encm1B0: &req.Encm1B.0.compress(),
                    Encm1B1: &req.Encm1B.1.compress(),
                    Encm2B0: &req.Encm2B.0.compress(),
                    Encm2B1: &req.Encm2B.1.compress(),
                    Encm4B0: &req.Encm4B.0.compress(),
                    Encm4B1: &req.Encm4B.1.compress(),
                    D: &req.D.compress(),
                },
            )?;

            // Compute the MAC on the visible attributes
            let mut rng = rand::thread_rng();
            let b = Scalar::random(&mut rng);
            let P = &b * Btable;
            let QHc =
                (self.privkey.x[0] + (self.privkey.x[3] * req.m3 + self.privkey.x[5] * req.m5)) * P;

            // El Gamal encrypt it to the public key req.D
            let s = Scalar::random(&mut rng);
            let EncQHc = (&s * Btable, QHc + s * req.D);

            // Homomorphically compute the part of the MAC corresponding to
            // the blinded attributes
            let t1 = self.privkey.x[1] * b;
            let T1 = &t1 * Atable;
            let EncQ1 = (t1 * req.Encm1B.0, t1 * req.Encm1B.1);
            let t2 = self.privkey.x[2] * b;
            let T2 = &t2 * Atable;
            let EncQ2 = (t2 * req.Encm2B.0, t2 * req.Encm2B.1);
            let t4 = self.privkey.x[4] * b;
            let T4 = &t4 * Atable;
            let EncQ4 = (t4 * req.Encm4B.0, t4 * req.Encm4B.1);

            let EncQ = (
                EncQHc.0 + EncQ1.0 + EncQ2.0 + EncQ4.0,
                EncQHc.1 + EncQ1.1 + EncQ2.1 + EncQ4.1,
            );

            let mut transcript = Transcript::new(b"Blind124 5 issuing proof");
            let piBlindIssue = blindissue::prove_compact(
                &mut transcript,
                blindissue::ProveAssignments {
                    A: &A,
                    B: &B,
                    P: &P,
                    EncQ0: &EncQ.0,
                    EncQ1: &EncQ.1,
                    X0: &self.pubkey.X[0],
                    X1: &self.pubkey.X[1],
                    X2: &self.pubkey.X[2],
                    X3: &self.pubkey.X[3],
                    X4: &self.pubkey.X[4],
                    X5: &self.pubkey.X[5],
                    P3: &(req.m3 * P),
                    P5: &(req.m5 * P),
                    T1: &T1,
                    T2: &T2,
                    T4: &T4,
                    D: &req.D,
                    Encm1B0: &req.Encm1B.0,
                    Encm1B1: &req.Encm1B.1,
                    Encm2B0: &req.Encm2B.0,
                    Encm2B1: &req.Encm2B.1,
                    Encm4B0: &req.Encm4B.0,
                    Encm4B1: &req.Encm4B.1,
                    x0: &self.privkey.x[0],
                    x0tilde: &self.privkey.x0tilde,
                    x1: &self.privkey.x[1],
                    x2: &self.privkey.x[2],
                    x3: &self.privkey.x[3],
                    x4: &self.privkey.x[4],
                    x5: &self.privkey.x[5],
                    s: &s,
                    b: &b,
                    t1: &t1,
                    t2: &t2,
                    t4: &t4,
                },
            )
            .0;

            Ok(CredentialResponse {
                P,
                EncQ,
                T1,
                T2,
                T4,
                piBlindIssue,
            })
        }
    }

    pub fn verify(
        state: CredentialRequestState,
        resp: CredentialResponse,
        pubkey: &IssuerPubKey,
    ) -> Result<Credential, ProofError> {
        let A: &RistrettoPoint = &CMZ_A;
        let B: &RistrettoPoint = &CMZ_B;

        if resp.P.is_identity() {
            return Err(ProofError::VerificationFailure);
        }

        let mut transcript = Transcript::new(b"Blind124 5 issuing proof");
        blindissue::verify_compact(
            &resp.piBlindIssue,
            &mut transcript,
            blindissue::VerifyAssignments {
                A: &A.compress(),
                B: &B.compress(),
                P: &resp.P.compress(),
                EncQ0: &resp.EncQ.0.compress(),
                EncQ1: &resp.EncQ.1.compress(),
                X0: &pubkey.X[0].compress(),
                X1: &pubkey.X[1].compress(),
                X2: &pubkey.X[2].compress(),
                X3: &pubkey.X[3].compress(),
                X4: &pubkey.X[4].compress(),
                X5: &pubkey.X[5].compress(),
                P3: &(state.m3 * resp.P).compress(),
                P5: &(state.m5 * resp.P).compress(),
                T1: &resp.T1.compress(),
                T2: &resp.T2.compress(),
                T4: &resp.T4.compress(),
                D: &state.D.compress(),
                Encm1B0: &state.Encm1B.0.compress(),
                Encm1B1: &state.Encm1B.1.compress(),
                Encm2B0: &state.Encm2B.0.compress(),
                Encm2B1: &state.Encm2B.1.compress(),
                Encm4B0: &state.Encm4B.0.compress(),
                Encm4B1: &state.Encm4B.1.compress(),
            },
        )?;

        // Decrypt EncQ
        let Q = resp.EncQ.1 - (state.d * resp.EncQ.0);

        Ok(Credential {
            P: resp.P,
            Q,
            m: vec![
                Scalar::zero(),
                state.m1,
                state.m2,
                state.m3,
                state.m4,
                state.m5,
            ],
        })
    }
}

// A submodule for showing credentials with 5 attributes, blinding
// attributes 3, 4, and 5, and displaying attributes 1 and 2.  As above,
// this could possibly be generated by a Rust macro in the future.
pub mod show_blind345_5 {
    use curve25519_dalek::ristretto::RistrettoBasepointTable;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::IsIdentity;

    use zkp::CompactProof;
    use zkp::ProofError;
    use zkp::Transcript;
    use serde::Serialize;
    use serde::Deserialize;

    use super::{Credential, Issuer, IssuerPubKey, CMZ_A, CMZ_A_TABLE};

    // A typo in the Hyphae paper (Section 4.4): P must also be sent to
    // the issuer in the credential presentation message.
    #[derive(Serialize, Deserialize)]
    pub struct ShowMessage {
        pub P: RistrettoPoint,
        m1: Scalar,
        m2: Scalar,
        Cm3: RistrettoPoint,
        Cm4: RistrettoPoint,
        Cm5: RistrettoPoint,
        CQ: RistrettoPoint,
        piCredShow: CompactProof,
    }

    #[derive(Debug)]
    pub struct VerifiedCredential {
        pub m1: Scalar,
        pub m2: Scalar,
        pub Cm3: RistrettoPoint,
        pub Cm4: RistrettoPoint,
        pub Cm5: RistrettoPoint,
    }

    // If you want to prove additional statements about the blinded
    // attributes when showing them, this is the place to add those
    // statements (and also the code that creates and verifies this
    // proof).
    define_proof! {
        show,
        "Blind345 5 showing proof",
        (m3, m4, m5, z3, z4, z5, negzQ),
        (P, Cm3, Cm4, Cm5, V, X3, X4, X5),
        (A) :
        Cm3 = (m3*P + z3*A),
        Cm4 = (m4*P + z4*A),
        Cm5 = (m5*P + z5*A),
        V = (z3*X3 + z4*X4 + z5*X5 + negzQ*A)
    }

    pub fn show(cred: &Credential, pubkey: &IssuerPubKey) -> (Scalar, ShowMessage) {
        let A: &RistrettoPoint = &CMZ_A;
        let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

        // Reblind P and Q
        let mut rng = rand::thread_rng();
        let t = Scalar::random(&mut rng);
        let P = t * cred.P;
        let Q = t * cred.Q;

        // Form Pedersen commitments to the blinded attributes
        let z3 = Scalar::random(&mut rng);
        let z4 = Scalar::random(&mut rng);
        let z5 = Scalar::random(&mut rng);
        let Cm3 = cred.m[3] * P + &z3 * Atable;
        let Cm4 = cred.m[4] * P + &z4 * Atable;
        let Cm5 = cred.m[5] * P + &z5 * Atable;

        // Form a Pedersen commitment to the MAC Q
        // We flip the sign of zQ from that of the Hyphae paper so that
        // the ZKP has a "+" instead of a "-", as that's what the zkp
        // macro supports.
        let negzQ = Scalar::random(&mut rng);
        let CQ = Q - &negzQ * Atable;

        // Compute the "error factor"
        let V = z3 * pubkey.X[3] + z4 * pubkey.X[4] + z5 * pubkey.X[5] + &negzQ * Atable;

        // Create the ZKP
        let mut transcript = Transcript::new(b"Blind345 5 showing proof");
        let piCredShow = show::prove_compact(
            &mut transcript,
            show::ProveAssignments {
                A: &A,
                P: &P,
                Cm3: &Cm3,
                Cm4: &Cm4,
                Cm5: &Cm5,
                V: &V,
                X3: &pubkey.X[3],
                X4: &pubkey.X[4],
                X5: &pubkey.X[5],
                m3: &cred.m[3],
                m4: &cred.m[4],
                m5: &cred.m[5],
                z3: &z3,
                z4: &z4,
                z5: &z5,
                negzQ: &negzQ,
            },
        )
        .0;
        (z3, 
        ShowMessage {
            P,
            m1: cred.m[1],
            m2: cred.m[2],
            Cm3,
            Cm4,
            Cm5,
            CQ,
            piCredShow,
        })
    }

    impl Issuer {
        // Verify a showing of an attribute from a user to the issuer
        // with 5 credentials, of which attributes 3, 4, and 5 are
        // blinded, and attributes 1 and 2 are revealed.  The issuer
        // will end up with verified Pedersen commitments Cm3, Cm4, Cm5
        // to the blinded attributes, so that additional things can be
        // proved about those attributes in zero knowledge if desired.
        pub fn verify_blind345_5(
            &self,
            showmsg: ShowMessage,
        ) -> Result<(RistrettoPoint, VerifiedCredential), ProofError> {
            let A: &RistrettoPoint = &CMZ_A;

            if showmsg.P.is_identity() {
                return Err(ProofError::VerificationFailure);
            }

            // Recompute the "error factor" using knowledge of our own
            // (the issuer's) private key instead of knowledge of the
            // hidden attributes
            let Vprime = (self.privkey.x[0]
                + (self.privkey.x[1] * showmsg.m1 + self.privkey.x[2] * showmsg.m2))
                * showmsg.P
                + self.privkey.x[3] * showmsg.Cm3
                + self.privkey.x[4] * showmsg.Cm4
                + self.privkey.x[5] * showmsg.Cm5
                - showmsg.CQ;

            // Verify the ZKP using Vprime
            let mut transcript = Transcript::new(b"Blind345 5 showing proof");
            show::verify_compact(
                &showmsg.piCredShow,
                &mut transcript,
                show::VerifyAssignments {
                    A: &A.compress(),
                    P: &showmsg.P.compress(),
                    Cm3: &showmsg.Cm3.compress(),
                    Cm4: &showmsg.Cm4.compress(),
                    Cm5: &showmsg.Cm5.compress(),
                    V: &Vprime.compress(),
                    X3: &self.pubkey.X[3].compress(),
                    X4: &self.pubkey.X[4].compress(),
                    X5: &self.pubkey.X[5].compress(),
                },
            )?;
            Ok((showmsg.P, VerifiedCredential {
                m1: showmsg.m1,
                m2: showmsg.m2,
                Cm3: showmsg.Cm3,
                Cm4: showmsg.Cm4,
                Cm5: showmsg.Cm5,
            }))
        }
    }
}
