# Jerks-Whistling-Tunes (JWT)

A Clojure library designed to create and verify Json Web Tokens (JWT).

## Usage

`[jerks-whistling-tunes "0.2.2"]`

[![Build Status](https://travis-ci.org/aprobus/jerks-whistling-tunes.svg?branch=master)](https://travis-ci.org/aprobus/jerks-whistling-tunes)

```clojure
(ns my-app
  (:require [jerks-whistling-tunes.core :as core]
            [jerks-whistling-tunes.sign :as sign])
```

### Verifying a token

There are two main validation functions:

```clojure
(valid? "header.claims.signature") ; Returns true/false
(validate "header.claims.signature") ; Returns decoded claims if valid, nil otherwise
```

By default, only the structure of the JWT is validated. Checks can be included
by adding them to the validate function.

```clojure
(def sign-hs256 (sign/hs256 "secret"))
(valid? "header.claims.signature" (signature sign-hs256)
                                  exp
                                  nbf))
```

#### Signature

```clojure
(validate "header.claims." (signature sign/none))
```

#### Expired (exp)

```clojure
(validate "header.claims.signature" exp)
```

#### Not Before (nbf)

```clojure
(validate "header.claims.signature" nbf)
```

#### Issuer (iss)

```clojure
(validate "header.claims.signature" (iss "issuer"))
```

#### Subject (sub)

```clojure
(validate "header.claims.signature" (sub "subject"))
```

#### Audience (aud)

```clojure
(validate "header.claims.signature" (aud "audience"))
```

#### Issued At (iat)

```clojure
(validate "header.claims.signature" iat)
```

### Creating a token

```clojure
(encode {:super_admin true} (sign/hs256 "secret"))
```

## Supported Algorithms

All algorithms are under in the `jerks-whistling-tunes.sign` namespace.

```clojure
(ns my-app
  (:require [jerks-whistling-tunes.sign :as sign]
            [jerks-whistling-tunes.utils :refer [decode-base-64]]))

(sign/hs256 "secret")
(sign/hs384 "secret")
(sign/hs512 (decode-base-64 "my-encoded-secret"))

; Supports either a java.security.KeyPair or a java.security.PublicKey
; KeyPairs support all operations, while a Public can only be used for verification
(sign/rs256 public-key)
(sign/rs384 key-pair)
(sign/rs512 key-pair)

(sign/ec256 public-key)
(sign/ec384 key-pair)
(sign/ec512 key-pair)

sign/none
```

## License

Copyright © 2015 Aaron Probus

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
