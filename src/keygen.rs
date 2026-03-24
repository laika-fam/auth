use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub kid: uuid::Uuid,
    pub public: jsonwebkey::JsonWebKey,
    pub private: jsonwebkey::JsonWebKey,
}

/// Derive a new key ID and JWK pair from a newly generated RSA keypair.
#[expect(clippy::expect_used, reason = "setup-time function")]
pub fn generate() -> Jwks {
    let rsa = openssl::rsa::Rsa::generate(4096).expect("rsa keygen");
    let k = jsonwebkey::Key::RSA {
        public: jsonwebkey::RsaPublic {
            e: jsonwebkey::PublicExponent,
            n: rsa.n().to_vec().into(),
        },
        private: Some(jsonwebkey::RsaPrivate {
            d: rsa.d().to_vec().into(),
            p: rsa.p().map(|p| p.to_vec().into()),
            q: rsa.q().map(|q| q.to_vec().into()),
            dp: rsa.dmp1().map(|dmp1| dmp1.to_vec().into()),
            dq: rsa.dmq1().map(|dmq1| dmq1.to_vec().into()),
            qi: rsa.iqmp().map(|iqmp| iqmp.to_vec().into()),
        }),
    };
    let public = k
        .clone()
        .to_public()
        .expect("there is a public part")
        .into_owned();
    let private = k;

    let kid = uuid::Uuid::new_v4();

    let mut public_jwk = jsonwebkey::JsonWebKey::new(public);
    public_jwk
        .set_algorithm(jsonwebkey::Algorithm::RS256)
        .expect("RS256 is correct for an RSA key");
    public_jwk.key_id = Some(kid.to_string());
    let mut private_jwk = jsonwebkey::JsonWebKey::new(private);
    private_jwk
        .set_algorithm(jsonwebkey::Algorithm::RS256)
        .expect("RS256 is correct for an RSA key");
    private_jwk.key_id = Some(kid.to_string());

    Jwks {
        kid,
        public: public_jwk,
        private: private_jwk,
    }
}
