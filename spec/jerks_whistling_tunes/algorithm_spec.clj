(ns jerks-whistling-tunes.algorithm-spec
  (:require [jerks-whistling-tunes.algorithm :refer :all]
            [speclj.core :refer :all]))

(def unsigned-jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ")

(def secret "secret")

(describe "jerks-whistling-tunes.algorithm"
  (describe "hs256"
    (it "encodes the string"
      (should= "eoaDVGTClRdfxUZXiPs3f8FmJDkDE_VCQFXqKxpLsts"
               ((hs256 secret) unsigned-jwt)))))

(run-specs)
