INSERT INTO ROLE(id, name) VALUES(1,'ROLE_SUPER_ADMIN');
INSERT INTO ROLE(id, name) VALUES(2,'ROLE_USER');
INSERT INTO ROLE(id, name) VALUES(3,'ROLE_MANAGER');
INSERT INTO ROLE(id, name) VALUES(4,'ROLE_SUPER_ADMIN');


INSERT INTO USER(id, name, username, password) VALUES (1, 'admin', 'admin', '$2a$10$eACCYoNOHEqXve8aIWT8Nu3PkMXWBaOxJ9aORUYzfMQCbVBIhZ8tG');
INSERT INTO USER(id, name, username, password) VALUES (2, 'user1', 'user1', '$2a$10$eACCYoNOHEqXve8aIWT8Nu3PkMXWBaOxJ9aORUYzfMQCbVBIhZ8tG');
INSERT INTO USER(id, name, username, password) VALUES (3, 'user2', 'user2', '$2a$10$eACCYoNOHEqXve8aIWT8Nu3PkMXWBaOxJ9aORUYzfMQCbVBIhZ8tG');
INSERT INTO USER(id, name, username, password) VALUES (4, 'user3', 'user3', '$2a$10$eACCYoNOHEqXve8aIWT8Nu3PkMXWBaOxJ9aORUYzfMQCbVBIhZ8tG');

INSERT INTO USER_ROLES ( ROLES_ID , USER_ID ) VALUES (1, 1);
INSERT INTO USER_ROLES ( ROLES_ID , USER_ID ) VALUES (2, 2);
INSERT INTO USER_ROLES ( ROLES_ID , USER_ID ) VALUES (3, 3);
INSERT INTO USER_ROLES ( ROLES_ID , USER_ID ) VALUES (4, 4);
