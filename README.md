# Whut dis? 

This is a basic implementation of a web-application using the Python Flask library.

It is designed to be as secure as possible but there are probably some issues, so I don't recommend stealing this code unless you know what it does.



## Dependencies 
- flask
- flask_login
- flask_bouncer
- mysql-server
- mysql-client
- libmysqlclient-dev
- mysql-python
- virtualenv (python)


## MySQL Database Create String

CREATE TABLE users (
ID INT PRIMARY KEY AUTO_INCREMENT NOT NULL,
u_name VARCHAR(100) NOT NULL,
p_word VARCHAR(100) NOT NULL,
pj_salt VARCHAR(50) NOT NULL,
role VARCHAR(20) NOT NULL,
UNIQUE(u_name));

