CREATE TABLE users (
    id serial primary key,
    name text NOT NULL,
    password text NOT NULL,
    expert BOOLEAN NOT NULL,
    admin BOOLEAN NOT NULL
);

CREATE TABLE questions (
    id serial primary key,
    user_id integer NOT NULL,
    expert_id integer NOT NULL,
    question_text text NOT NULL,
    answer_text text
);