(ns jerks-whistling-tunes.utils
  (:import org.apache.commons.codec.binary.Base64))

(def ^:private base-64-encoder (Base64. -1 (.getBytes "") true))

(defn decode-base-64
  "Returns the decoded base 64 url safe encoded string."
  [str]
  (.decode base-64-encoder str))

(defn encode-base-64
  "Returns a base 64 url safe encoded representation of the string"
  [bytes]
  (String. (.encode base-64-encoder bytes) "UTF-8"))
