CREATE DATABASE Criptify_Algorithm;

USE Criptify_Algorithm;



CREATE TABLE TB_Longitud(
	id_long INT PRIMARY KEY IDENTITY,
	long_bits INT NOT NULL,
	long_bytes AS (long_bits/8) PERSISTED
)

CREATE TABLE TB_Clave(
	id_clave INT PRIMARY KEY IDENTITY,
	txt_inicial VARCHAR(255),
	clave VARCHAR(255),
	id_long INT REFERENCES TB_Longitud(id_long),
	criptograma VARCHAR (255),
	txt_desencrip VARCHAR (255),
	fecha_creacion DATETIME DEFAULT GETDATE()
)

SELECT * FROM TB_Longitud;



INSERT INTO TB_Longitud(long_bits) 
VALUES 
(128)
GO

INSERT INTO TB_Longitud(long_bits) 
VALUES 
(192)
GO

INSERT INTO TB_Longitud(long_bits) 
VALUES 
(256)
GO


