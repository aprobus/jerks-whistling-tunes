(ns jerks-whistling-tunes.algorithm-spec
  (:require [jerks-whistling-tunes.algorithm :refer :all]
            [speclj.core :refer :all]))

(def secret "secret")

(describe "jerks-whistling-tunes.algorithm"
  (describe "hs256"
    (with unsigned-jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ")

    (it "encodes the string"
      (should= "eoaDVGTClRdfxUZXiPs3f8FmJDkDE_VCQFXqKxpLsts"
               ((hs256 secret) @unsigned-jwt)))

    (it "specifies an alg"
      (should= "HS256"
               (:alg (meta (hs256 secret))))))

  (describe "hs384"
    (with unsigned-jwt "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ")

    (it "encodes the string"
      (should= "KJinFn10CgjbSBF0nUixqiqlFNZFoatdanR2ce739Ix-OIsqRpiZcApEUvVHKEKw"
               ((hs384 secret) @unsigned-jwt)))

    (it "specifies an alg"
      (should= "HS384"
               (:alg (meta (hs384 secret))))))

  (describe "hs512"
    (with unsigned-jwt "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ")

    (it "encodes the string"
      (should= "fSCfxDB4cFVvzd6IqiNTuItTYiv-tAp5u5XplJWRDBGNF1rgGn1gyYK9LuHobWWpwqCzI7pEHDlyrbNHaQJmqg"
               ((hs512 secret) @unsigned-jwt)))

    (it "specifies an alg"
      (should= "HS512"
               (:alg (meta (hs512 secret)))))))

(run-specs)
