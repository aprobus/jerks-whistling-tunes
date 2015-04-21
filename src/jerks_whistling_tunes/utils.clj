(ns jerks-whistling-tunes.utils)

(def ^:private base-64-encoder (org.apache.commons.codec.binary.Base64. true))

(defn decode-base-64 [str]
  (.decode base-64-encoder str))

(defn encode-base-64 [bytes]
  (let [result (String. (.encode base-64-encoder bytes) "UTF-8")
        len-without-newline (- (count result) 2)]
    (.substring result 0 len-without-newline)))
