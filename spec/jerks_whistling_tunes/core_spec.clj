(ns jerks-whistling-tunes.core-spec
  (:require [jerks-whistling-tunes.core :refer :all]
            [speclj.core :refer :all]))

(def jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.eoaDVGTClRdfxUZXiPs3f8FmJDkDE_VCQFXqKxpLsts")

(def secret "my secret")

(describe "jerks-whistling-tunes.core"
  (describe "sign"
    (it "signs empty claims"
      (should= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.bYbzTu1BlXUhf-V8G0JCR2yarRl9J7fzZvssGRentYY"
               (sign "HS256" secret {})))

    (it "signs simple claim"
      (should= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.A2MH3GUuTTdUaFab1h8-ZxKGBEeVLfeIT-RA__SgLkY"
               (sign "HS256" secret {:iss "foo"}))))

  (describe "valid?"
    (it "verfies token"
      (should (valid? "secret" jwt)))

    (it "rejects empty segments"
      (should-not (valid? "secret" "")))

    (it "rejects one segments"
      (should-not (valid? "secret" "crypto")))

    (it "rejects two segments"
      (should-not (valid? "secret" "much.crypto")))

    (it "rejects four segments"
      (should-not (valid? "secret" "much.crypto.so.token")))

    (it "rejects tokens by signature token"
      (should-not (valid? "wrongsecret" jwt)))

    (it "rejects null tokens"
      (should-not (valid? "secret" nil)))

    (it "rejects unsupported algorithms"
      (should-not (valid? secret "eyJhbGciOiJkb2dlIiwidHlwIjoiSldUIn0.e30.GCsA4jZgcT3deNioC4k4KofE_mnanJQDVzv3eloO9uk")))

    (context "with an unexpired token"
      (with token (sign "HS256" secret {:exp (+ (current-time-secs) 2)}))

      (it "accepts the token"
        (should (valid? secret @token))))

    (context "with an expired token"
      (with token (sign "HS256" secret {:exp (- (current-time-secs) 2)}))

      (it "rejects the token"
        (should-not (valid? secret @token))))

    (context "with an audience"
      (with token (sign "HS256" secret {:aud "king"}))

      (it "rejects the invalid audience"
        (should-not (valid? secret @token :aud "joker")))

      (it "accepts the right audience"
        (should (valid? secret @token :aud "king"))))

    (context "with an issuer"
      (with token (sign "HS256" secret {:iss "king"}))

      (it "rejects the invalid issuer"
        (should-not (valid? secret @token :iss "joker")))

      (it "accepts the right issuer"
        (should (valid? secret @token :iss "king"))))

    (context "with a encoded secret"
      (with token (sign "HS256" secret {} :secret-fn decode-base-64))

      (it "should accept token"
        (should (valid? secret @token :secret-fn decode-base-64))))))

(run-specs)
