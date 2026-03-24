pub mod model;
pub mod schema;

/// From the given Diesel column ZSTs, generate a changeset tuple acceptable to `.do_update().set(...)`.
#[macro_export]
macro_rules! set_excluded {
    ($( $col:path, ) +) => {
        {
            use diesel::ExpressionMethods as _;
            (
                $(
                    $col.eq(diesel::upsert::excluded($col)),
                )*
            )
        }
    };
}
