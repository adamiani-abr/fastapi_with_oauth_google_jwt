# fastapi_with_oauth_google_jwt

## Possible Issues

1. JWT access token and refresh token **TTL different**
   1. Set in two places:
      1. `FastAPI` auth service JWT token payload `exp`
      2. `Flask` frontend web service Cookies
   2. Possible Issues:
      1. `Flask` frontend Cookie TTL longer the auth token `exp` (Cookie outlives token)
         1. Result:
            1. Browser will keep sending the cookie, but token already expired (or refresh key already vanished from Redis)
            2. Every request will 401 or every refresh attempt will fail—even though the cookie is still present
      2. `Flask` frontend Cookie TTL shorter the auth token `exp` (token outlives Cookie)
         2. Result:
            1. Browser silently drops cookie while token still technically valid on server side
            2. User’s POV → get logged out “too early,” because no cookie = no credentials, even though token not expired yet
