create table refresh_token (
    id uuid primary key not null default gen_random_uuid(),
    user_id varchar not null,
    email varchar not null,
    name varchar not null,
    picture varchar null,
    client_id varchar not null,
    scope varchar not null,
    google_refresh_token varchar null,
    expires timestamp with time zone not null
);