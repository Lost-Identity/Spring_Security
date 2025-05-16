--this scripts we got from JdbcUserDetailsManager --> JdbcDaoImpl --> DEFAULT_USER_SCHEMA_DDL_LOCATION
create table users(username varchar(50) not null primary key,password varchar(500) not null,enabled boolean not null);
create table authorities (username varchar(50) not null,authority varchar(50) not null,constraint fk_authorities_users foreign key(username) references users(username));
create unique index ix_auth_username on authorities (username,authority);

INSERT IGNORE INTO `users` VALUES ('user', '{noop}Ajay@12345', '1');
INSERT IGNORE INTO `authorities` VALUES ('user', 'read');

INSERT IGNORE INTO `users` VALUES ('admin', '{bcrypt}$2a$12$cFSBadc.pDJLZiY00xL5rODPZPk.hyl/C1mTCL124zarHqd1oGdaC', '1');
INSERT IGNORE INTO `authorities` VALUES ('admin', 'admin');

--Creating custom table for authentication
CREATE TABLE `customer` (
`id` int NOT NULL AUTO_INCREMENT,
`email` varchar(45) NOT NULL,
`pwd` varchar(200) NOT NULL,
`role` varchar(45) NOT NULL,
PRIMARY KEY (`id`)
);

INSERT INTO `customer` (`email`, `pwd`, `role`) VALUES ('happy@ex.com', '{noop}Eazybytes@12345', 'read');
INSERT INTO `customer` (`email`, `pwd`, `role`) VALUES ('admin@ex.com', '{bcrypt}$2a$12$cFSBadc.pDJLZiY00xL5rODPZPk.hyl/C1mTCL124zarHqd1oGdaC', 'read');