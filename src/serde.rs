pub(crate) mod option_non_nil_uuid_simple {
    use serde::Deserialize as _;

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
            .map(|u| uuid::NonNilUuid::try_from(u.into_uuid()).ok())
            .flatten())
    }
}
