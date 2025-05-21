# OATProxy: An ATProto OAuth Proxy

**ALPHA SOFTWARE, USE AT YOUR OWN RISK!**

Tired of getting logged out of your AT Protocol applications every 24 hours?
Introducing OATProxy! OATProxy acts as a transparent passthrough XRPC proxy
between your front-end application, upgrading your users from
frequently-expiring "public" OAuth sessions to robust, hearty "confidental"
OAuth sessions.

| Session Type | Inactivity Timeout | Max Session Length |
| ------------ | ------------------ | ------------------ |
| Public       | 24 hours           | 7 days             |
| Confidental  | 1 month            | 1 year             |

OATProxy exists as both a Go library for embedding in applications and as a
standalone microservice.
