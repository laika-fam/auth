-- Your SQL goes here
create table jwk (
    id varchar not null primary key,
    key_data jsonb not null
);