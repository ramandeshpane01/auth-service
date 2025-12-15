# Auth Service

A production-style authentication service implementing JWT-based stateless authentication with refresh token rotation and Redis-backed token storage.

## Features
- JWT access tokens
- Refresh token rotation
- Device-based sessions
- Redis-backed refresh tokens (hashed)
- Logout with token invalidation
- Rate limiting for auth endpoints
- Stateless security architecture

## Auth Flow
1. User logs in → receives access + refresh token
2. Access token expires → refresh token used
3. Refresh token is rotated on every refresh
4. Logout invalidates refresh token

## Tech Stack
- Spring Boot 3
- Spring Security
- Redis
- JWT (jjwt)
