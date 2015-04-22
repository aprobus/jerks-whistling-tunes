(ns jerks-whistling-tunes.utils-spec
  (:require [jerks-whistling-tunes.utils :refer :all]
            [speclj.core :refer :all]))

(def hello-bytes (.getBytes "hello" "UTF-8"))
(def sentence-bytes (.getBytes "this is a long string. It keeps going and doesn't seem to stop" "UTF-8"))

(describe "jerks-whistling-tunes.utils-spec"
  (describe "encode-base-64"
    (it "encodes the bytes"
      (should= "aGVsbG8"
               (encode-base-64 hello-bytes)))

    (it "strips out newlines"
      (should= "dGhpcyBpcyBhIGxvbmcgc3RyaW5nLiBJdCBrZWVwcyBnb2luZyBhbmQgZG9lc24ndCBzZWVtIHRvIHN0b3A"
               (encode-base-64 sentence-bytes))))

  (describe "decode-base-64"
    (it "decodes the encoded string"
      (should= (vec hello-bytes)
               (vec (decode-base-64 "aGVsbG8"))))))

(run-specs)
