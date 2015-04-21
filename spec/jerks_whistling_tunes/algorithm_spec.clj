(ns jerks-whistling-tunes.algorithm-spec
  (:require [jerks-whistling-tunes.algorithm :refer :all]
            [speclj.core :refer :all]))

(def unsigned-jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ")

(def secret "secret")

(describe "jerks-whistling-tunes.algorithm"
  (describe "hs256"
    (it "encodes the string"
      (should= "eoaDVGTClRdfxUZXiPs3f8FmJDkDE_VCQFXqKxpLsts"
               ((hs256 secret) unsigned-jwt))))

  (describe "hs384"
    (it "encodes the string"
      (should= "Wk-GxVm14_MHtn7esykHAFOUwob1Z8PXMdvFbnAh2JnluyV6KAe6NEHZXG-8ZZDT"
               ((hs384 secret) unsigned-jwt))))

  (describe "hs512"
    (it "encodes the string"
      (should= "0JRoNr4i-fz-Pz0w0No331-_8pq9wnSM3Ic5W9dZOCT8gFTfu8bJpd8nV5ELUonPY1fOnIQScKeA\r\ncc8niKLK3w"
               ((hs512 secret) unsigned-jwt)))))

(run-specs)
