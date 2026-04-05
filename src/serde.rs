pub(crate) mod option_non_nil_uuid_simple {
    #![allow(dead_code, reason = "can't hurt to have both if only one is used")]

    use serde::Deserialize as _;

    #[expect(clippy::ref_option, reason = "this is how serde works, idiom doesn't matter")]
    pub fn serialize<S>(u: &Option<uuid::NonNilUuid>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde::Serialize::serialize(&u.map(|u| u.get().simple()), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<uuid::NonNilUuid>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Option::<uuid::fmt::Simple>::deserialize(deserializer)?
            .and_then(|u| uuid::NonNilUuid::try_from(u.into_uuid()).ok()))
    }
}
