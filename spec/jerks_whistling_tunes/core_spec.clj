(ns jerks-whistling-tunes.core-spec
  (:require [jerks-whistling-tunes.core :refer :all]
            [speclj.core :refer :all]))

(def jwt-hs256 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.asdf")

(def sign-constant (constantly "asdf"))

(describe "jerks-whistling-tunes.core"
  (describe "sign"
    (it "signs empty claims"
      (should= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.asdf"
               (sign "HS256" {} sign-constant)))

    (it "signs simple claim"
      (should= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.asdf"
               (sign "HS256" {:iss "foo"} sign-constant))))

  (describe "valid?"
    (it "verfies token"
      (should (valid? sign-constant jwt-hs256)))

    (it "rejects empty segments"
      (should-not (valid? sign-constant "")))

    (it "rejects one segments"
      (should-not (valid? sign-constant "crypto")))

    (it "rejects two segments"
      (should-not (valid? (constantly "") "hi.bye")))

    (it "rejects four segments"
      (should-not (valid? sign-constant "much.crypto.so.token")))

    (it "rejects tokens by signature token"
      (should-not (valid? (constantly "wrong-sig") jwt-hs256)))

    (it "rejects null tokens"
      (should-not (valid? sign-constant nil)))

    (context "with an unexpired token"
      (with token (sign "HS256" {:exp (+ (current-time-secs) 2)} sign-constant))

      (it "accepts the token"
        (should (valid? sign-constant @token))))

    (context "with an expired token"
      (with token (sign "HS256" {:exp (- (current-time-secs) 2)} sign-constant))

      (it "rejects the token"
        (should-not (valid? sign-constant @token))))

    (context "with an audience"
      (with token (sign "HS256" {:aud "king"} sign-constant))

      (it "rejects the invalid audience"
        (should-not (valid? sign-constant @token :aud "joker")))

      (it "accepts the right audience"
        (should (valid? sign-constant @token :aud "king"))))

    (context "with an issuer"
      (with token (sign "HS256" {:iss "king"} sign-constant))

      (it "rejects the invalid issuer"
        (should-not (valid? sign-constant @token :iss "joker")))

      (it "accepts the right issuer"
        (should (valid? sign-constant @token :iss "king"))))

    (describe "validate"
      (with token (sign "HS256" {:sub "king"} sign-constant))

      (it "is falsy with a bad token"
        (should-not (validate (constantly "invalid") @token)))

      (it "returns the claims when token is valid"
        (should= {:sub "king"}
                 (validate sign-constant @token))))))

(run-specs)
