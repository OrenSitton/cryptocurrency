CREATE DATABASE IF NOT EXISTS Blockchain;
CREATE TABLE if not EXISTS Blocks (
    id int UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    block_number INT UNSIGNED, time_created TIMESTAMP,
    size MEDIUMINT, hash VARCHAR(64) NOT NULL, difficulty SMALLINT,
    nonce MEDIUMINT,
    merkle_root_hash VARCHAR(64),
    transactions LONGBLOB,
    self_hash VARCHAR(64));