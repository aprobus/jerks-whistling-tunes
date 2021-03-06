(ns jerks-whistling-tunes.core-spec
  (:require [jerks-whistling-tunes.core :refer :all]
            [jerks-whistling-tunes.sign :as sign]
            [speclj.core :refer :all]))

(def jwt-hs256 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.asdf")

(defrecord Signer [alg sig]
  sign/Algorithm

  (jwt-alg [this] alg)

  (sign [this body]
    sig)

  (valid-signature? [this body signature]
    (= (.sign this body) signature)))

(describe "jerks-whistling-tunes.core"
  (with signer (Signer. "HS256" "asdf"))

  (describe "encode"

    (it "signs empty claims"
      (should= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.asdf"
               (encode {} @signer)))

    (it "signs simple claim"
      (should= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.asdf"
               (encode {:iss "foo"} @signer))))

  (describe "valid?"
    (with token (encode { } @signer))

    (it "verfies token"
      (should (valid? jwt-hs256)))

    (it "rejects empty segments"
      (should-not (valid? "")))

    (it "rejects one segments"
      (should-not (valid? "crypto")))

    (it "accepts empty signature"
      (should (valid? "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.")))

    (it "rejects four segments"
      (should-not (valid? "much.crypto.so.token")))

    (it "rejects null tokens"
      (should-not (valid? nil)))

    (it "rejects invalid json header"
      (should-not (valid? "yJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.asdf")))

    (it "rejects invalid json claims"
      (should-not (valid? "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.yJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.asdf")))

    (it "is invalid with failing checks"
      (should-not (valid? @token (fn [a b c] true) (fn [a b c] false))))

    (it "is valid with no checks"
      (should (valid? @token)))

    (it "is valid with passing checks"
      (should (valid? @token (fn [a b c] true)))))

  (describe "validate"
    (with token (encode {:sub "king"} @signer))

    (it "is falsy with a bad token"
      (should-not (validate @token (fn [a b c] false))))

    (it "returns the claims when token is valid"
      (should= {:sub "king"}
               (validate @token))))

  (describe "iss"
    (it "is valid when iss matches"
      (should ((iss "hi") {} {:iss "hi"} [])))

    (it "is invalid when iss is different"
      (should-not ((iss "hi") {} {:iss "bye"} [])))

    (it "is invalid when iss is missing"
      (should-not ((iss "hi") {} {} []))))

  (describe "exp"
    (it "is valid for future tokens"
      (should (exp {} {:exp (+ (current-time-secs) 22)} [])))

    (it "is invalid for expired tokens"
      (should-not (exp {} {:exp (- (current-time-secs) 1)} [])))

    (it "is invalid for claims missing exp"
      (should-not (exp {} {} [])))

    (it "rejects values of the wrong type"
      (should-not (exp {} {:exp "blah"} []))))

  (describe "nbf"
    (it "is valid after nbf"
      (should (nbf {} {:nbf (current-time-secs)} [])))

    (it "is invalid before nbf"
      (should-not (nbf {} {:nbf (+ (current-time-secs) 10)} [])))

    (it "is invalid for claims missing nbf"
      (should-not (nbf {} {} [])))

    (it "rejects values of the wrong type"
      (should-not (nbf {} {:nbf "blah"} []))))

  (describe "iat"
    (it "is valid when iat is in the past"
      (should (iat {} {:iat (- (current-time-secs) 20)} [])))

    (it "is invalid when iat is in the future"
      (should-not (iat {} {:iat (+ (current-time-secs) 10)} [])))

    (it "is invalid for claims missing iat"
      (should-not (iat {} {} [])))

    (it "rejects values of the wrong type"
      (should-not (iat {} {:iat "blah"} []))))

  (describe "aud"
    (it "is valid when aud matches"
      (should ((aud "hi") {} {:aud "hi"} [])))

    (it "is invalid when aud is different"
      (should-not ((aud "hi") {} {:aud "bye"} [])))

    (it "is invalid when aud is missing"
      (should-not ((aud "hi") {} {} []))))

  (describe "sub"
    (it "is valid when sub matches"
      (should ((sub "hi") {} {:sub "hi"} [])))

    (it "is invalid when sub is different"
      (should-not ((sub "hi") {} {:sub "bye"} [])))

    (it "is invalid when sub is missing"
      (should-not ((sub "hi") {} {} []))))

  (describe "signature"
    (with signer (Signer. "custom" "signature"))

    (it "rejects when alg is not supported"
      (should-not ((signature) {:alg "invalid"} {} [])))

    (it "errors on duplicate algs"
      (should-throw (signature @signer @signer)))

    (it "rejects mismatched signatures"
      (should-not ((signature @signer) {:alg "custom"} {} ["header.claims" "invalid-signature"])))

    (it "accepts matched signatures"
      (should ((signature @signer) {:alg "custom"} {} ["header.claims" "signature"])))))

(run-specs)
