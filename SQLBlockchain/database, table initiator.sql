CREATE DATABASE IF NOT EXISTS Blockchain;
CREATE TABLE IF NOT EXISTS Blockchain.block (id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT, DATA LONGTEXT, prev_hash VARCHAR(64) NOT NULL);