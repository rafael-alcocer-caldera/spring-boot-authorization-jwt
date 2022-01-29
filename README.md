# SPRING BOOT AUTHORIZATION JWT

## Synopsis

The project is a Spring Boot Application for Authorization using JWT (JSON Web Token). 

## Motivation

I wanted to do an authorization service.

## Pre Requirements

- None


USING POSTMAN:
--------------

POST
http://localhost:9090/authorization

Body
----
```json
{
    "username": "xxx",
    "password": "yyy"
}
```

Response:
---------
```json
{
    "username": "xxx",
    "password": null,
    "jwt": "eyJhbGciOiJIUzUxMiJ9.eyJqdGkiOiI4M2ZiNDcxODg5Y2U0NTNkYmU4Y2E5ZDVkMWFkYjU4NCIsImlzcyI6InJhcGlkc2hvcCIsInN1YiI6InRva2VuIiwiZXhwIjoxNjQzNDMzNjQ5LCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXX0.UYvgcnWZElY1tlwA-I7pR7fyf3LSasNtaJpVdklk1DpoucQm4ERpAcTPxOQZopKmZ5TBRvEa5fnKJvoMSS3Bzw"
}
```

Eclipse Console:
----------------

&#35;&#35;&#35;&#35;&#35; username: xxx

&#35;&#35;&#35;&#35;&#35; password: yyy

&#35;&#35;&#35;&#35;&#35; webSecurityConfiguration.getSecretKey(): JvKyO3sH3QHpJTZ5aZikk9QdZY1wL5H0J47B9IRSRsD6nA7F25AzGnVc9P96Zwf0wwtgAvAMz+G24hVLUJ2n1A==

&#35;&#35;&#35;&#35;&#35; dateTime (including minutes added: Fri Jan 28 23:20:49 CST 2022

&#35;&#35;&#35;&#35;&#35; JWT: eyJhbGciOiJIUzUxMiJ9.eyJqdGkiOiI4M2ZiNDcxODg5Y2U0NTNkYmU4Y2E5ZDVkMWFkYjU4NCIsImlzcyI6InJhcGlkc2hvcCIsInN1YiI6InRva2VuIiwiZXhwIjoxNjQzNDMzNjQ5LCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXX0.UYvgcnWZElY1tlwA-I7pR7fyf3LSasNtaJpVdklk1DpoucQm4ERpAcTPxOQZopKmZ5TBRvEa5fnKJvoMSS3Bzw


## License

All work is under Apache 2.0 license