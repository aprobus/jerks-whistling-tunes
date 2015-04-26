(ns jerks-whistling-tunes.sign-spec
  (:require [jerks-whistling-tunes.sign :refer :all]
            [speclj.core :refer :all]))

(def secret "secret")

(def key-converter (org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter.))

(defn- load-rsa-key-pair* []
  (with-open [rdr (clojure.java.io/reader "resources/test/rsa.pem")]
    (->> rdr
      org.bouncycastle.openssl.PEMParser.
      .readObject
      (.getKeyPair key-converter))))
(def load-rsa-key-pair (memoize load-rsa-key-pair*))
(defn- load-public-key []
  (.getPublic (load-rsa-key-pair)))

(describe "jerks-whistling-tunes.sign"
  (with key-pair (load-rsa-key-pair))
  (with public-key (load-public-key))

  (describe "hs256"
    (with unsigned-jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ")
    (with signature "eoaDVGTClRdfxUZXiPs3f8FmJDkDE_VCQFXqKxpLsts")

    (it "encodes the string with a String secret"
      (should= @signature
               (.sign (hs256 secret) @unsigned-jwt)))

    (it "encodes the string with a byte[] secret"
      (should= @signature
               (.sign (hs256 (.getBytes secret)) @unsigned-jwt)))

    (it "accepts valid signatures"
      (should (.valid-signature? (hs256 secret) @unsigned-jwt @signature)))

    (it "rejects invalid signatures"
      (should-not (.valid-signature? (hs256 secret) @unsigned-jwt "bad_signature")))

    (it "specifies the alg"
      (should= "HS256"
               (.jwt-alg (hs256 secret)))))

  (describe "hs384"
    (with unsigned-jwt "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ")

    (it "encodes the string"
      (should= "KJinFn10CgjbSBF0nUixqiqlFNZFoatdanR2ce739Ix-OIsqRpiZcApEUvVHKEKw"
               (.sign (hs384 secret) @unsigned-jwt)))

    (it "specifies the alg"
      (should= "HS384"
               (.jwt-alg (hs384 secret)))))

  (describe "hs512"
    (with unsigned-jwt "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ")

    (it "encodes the string"
      (should= "fSCfxDB4cFVvzd6IqiNTuItTYiv-tAp5u5XplJWRDBGNF1rgGn1gyYK9LuHobWWpwqCzI7pEHDlyrbNHaQJmqg"
               (.sign (hs512 secret) @unsigned-jwt)))

    (it "specifies the alg"
      (should= "HS512"
               (.jwt-alg (hs512 secret)))))

  (describe "RS256"
    (with unsigned-jwt "my_token")
    (with signature "Ksz7hR-hKM7nyVM6EeC6giG96z1WdBzKiGgBH2BmURyW6LkTMp9NyzwXoczJNtsF7XYIqa7UbFh8q_tddUlMgfJhG61SG9qYpZHt36SdfDREvfTmUY_CA01JXI3qZ6ixGBKcn67is0N9oSa8D7gxgdNfnNktLNRlLyECfqDMc8w")

    (it "encodes the string"
      (should= @signature
               (.sign (rs256 @key-pair) @unsigned-jwt)))

    (it "errors when signing if private key is not given"
      (should-throw java.security.InvalidKeyException
                    (.sign (rs256 @public-key) @unsigned-jwt)))

    (it "accepts valid signatures"
      (should (.valid-signature? (rs256 @public-key) @unsigned-jwt @signature)))

    (it "rejects invalid signatures"
      (should-not (.valid-signature? (rs256 @public-key) @unsigned-jwt "bad_signature")))

    (it "specifies the alg"
      (should= "RS256"
               (.jwt-alg (rs256 @public-key)))))

  (describe "RS384"
    (it "encodes the string"
      (should= "Obyxj2vjawZtG-b8jnHzAT5YR7tjqHDZJhlQnYjkBxyRcWo0FUiAiiZi02DFwR32zVHkCND7q-GMO_ApKAubmFUz_2jf59-GahMqQis7cVqv56Zd2Xq_8WzBxacBLcaZdwqmBs88Mow0VyFf8E8ySZP-WP3aJSyiJlzfk4HZf1k"
               (.sign (rs384 @key-pair) "my_token")))

    (it "specifies the alg"
      (should= "RS384"
               (.jwt-alg (rs384 @key-pair)))))

  (describe "RS512"
    (it "encodes the string"
      (should= "if5Y5Cl0LBr1wx8wHsXQcHDZL85JJ-QXxW6lEa2jPW3GwqdeNrG_quENdUK8M8mMyKw5zN1Qv0YZku3FwE9OnhDUm9pf4jaE9x-NmSpoBoC2d82amVP0p5NNlErIUtIDadBcGuefRfXvFmK5qTx5Vd9W4LqTadNzqEYfwknu6kw"
               (.sign (rs512 @key-pair) "my_token")))

    (it "specifies the alg"
      (should= "RS512"
               (.jwt-alg (rs512 @key-pair)))))

  (describe "none"
    (it "encodes the string"
      (should= ""
               (.sign none "asdf")))

    (it "accepts valid signatures"
      (should (.valid-signature? none "asdf" "")))

    (it "rejects invalid signatures"
      (should-not (.valid-signature? none "asdf" "bad_signature")))

    (it "specifies the alg"
      (should= "none"
               (.jwt-alg  none)))))

(run-specs)
