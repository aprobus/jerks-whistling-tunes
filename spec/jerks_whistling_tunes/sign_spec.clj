(ns jerks-whistling-tunes.sign-spec
  (:require [jerks-whistling-tunes.sign :refer :all]
            [speclj.core :refer :all]))

(def secret "secret")

(describe "jerks-whistling-tunes.sign"
  (describe "hs256"
    (with unsigned-jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ")

    (it "encodes the string"
      (should= "eoaDVGTClRdfxUZXiPs3f8FmJDkDE_VCQFXqKxpLsts"
               ((hs256 secret) @unsigned-jwt)))

    (it "specifies the alg"
      (should= "HS256"
               (:alg (meta (hs256 secret))))))

  (describe "hs384"
    (with unsigned-jwt "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ")

    (it "encodes the string"
      (should= "KJinFn10CgjbSBF0nUixqiqlFNZFoatdanR2ce739Ix-OIsqRpiZcApEUvVHKEKw"
               ((hs384 secret) @unsigned-jwt)))

    (it "specifies the alg"
      (should= "HS384"
               (:alg (meta (hs384 secret))))))

  (describe "hs512"
    (with unsigned-jwt "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ")

    (it "encodes the string"
      (should= "fSCfxDB4cFVvzd6IqiNTuItTYiv-tAp5u5XplJWRDBGNF1rgGn1gyYK9LuHobWWpwqCzI7pEHDlyrbNHaQJmqg"
               ((hs512 secret) @unsigned-jwt)))

    (it "specifies the alg"
      (should= "HS512"
               (:alg (meta (hs512 secret))))))

  (describe "none"
    (it "encodes the string"
      (should= ""
               (none "asdf")))

    (it "specifies the alg"
      (should= "none"
               (:alg (meta none))))))

(run-specs)
