(ns jerks-whistling-tunes.core-spec
  (:require [jerks-whistling-tunes.core :refer :all]
            [speclj.core :refer :all]))

(def jwt-hs256 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.asdf")

(def sign-constant (with-meta (constantly "asdf")
                              {:alg "HS256"}))

(describe "jerks-whistling-tunes.core"
  (describe "sign"
    (it "signs empty claims"
      (should= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.asdf"
               (sign {} sign-constant)))

    (it "signs simple claim"
      (should= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.asdf"
               (sign {:iss "foo"} sign-constant))))

  (describe "valid?"
    (with token (sign { } sign-constant))

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

    (it "is invalid with failing claims checks"
      (should-not (valid? sign-constant @token (constantly false))))

    (it "is valid with passing claims checks"
      (should (valid? sign-constant @token (constantly true)))))

  (describe "validate"
    (with token (sign {:sub "king"} sign-constant))

    (it "is falsy with a bad token"
      (should-not (validate (constantly "invalid") @token)))

    (it "returns the claims when token is valid"
      (should= {:sub "king"}
               (validate sign-constant @token))))

  (describe "iss"
    (it "is valid when iss matches"
      (should ((iss "hi") {:iss "hi"})))

    (it "is invalid when iss is different"
      (should-not ((iss "hi") {:iss "bye"})))

    (it "is invalid when iss is missing"
      (should-not ((iss "hi") {}))))

  (describe "exp"
    (it "is valid for future tokens"
      (should (exp {:exp (+ (current-time-secs) 22)})))

    (it "is invalid for expired tokens"
      (should-not (exp {:exp (- (current-time-secs) 1)})))

    (it "is invalid for claims missing exp"
      (should-not (exp {}))))

  (describe "aud"
    (it "is valid when aud matches"
      (should ((aud "hi") {:aud "hi"})))

    (it "is invalid when aud is different"
      (should-not ((aud "hi") {:aud "bye"})))

    (it "is invalid when aud is mauding"
      (should-not ((aud "hi") {})))))

(run-specs)
