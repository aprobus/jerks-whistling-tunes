# Jerks-Whistling-Tunes (JWT)

A Clojure library designed to create and verify Json Web Tokens.

## Usage

### Verifying a token

Verify expiration, audience, and issuer
```clojure
(valid? "secret" "my.jwt.token" :aud "The king" 
                                :iss "His humble servant")
```

Verify only expiration:
```clojure
(valid? "secret" "my.jwt.token")
```

### Creating a token

```clojure
(sign "HS256" "secret" {:super_admin true})
```

## Supported Algorithms

* HS256

## License

Copyright © 2015 FIXME

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
