(ns jerks-whistling-tunes.utils)

(def ^:private base-64-encoder (org.apache.commons.codec.binary.Base64. -1 (.getBytes "") true))

(defn decode-base-64 [str]
  (.decode base-64-encoder str))

(defn encode-base-64 [bytes]
  (String. (.encode base-64-encoder bytes) "UTF-8"))
