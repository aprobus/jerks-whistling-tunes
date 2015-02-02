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
      (should-not (valid? "wrongsecret" jwt)))))

(run-specs)
