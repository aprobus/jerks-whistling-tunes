(ns jerks-whistling-tunes.utils
  (:import org.apache.commons.codec.binary.Base64))

(def ^:private ^Base64 base-64-encoder (Base64. -1 (.getBytes "") true))

(defn decode-base-64
  "Returns the decoded base 64 url safe encoded string."
  [s]
  (.decode base-64-encoder s))

(defn encode-base-64
  "Returns a base 64 url safe encoded representation of the string"
  [^bytes bs]
  (String. (.encode base-64-encoder bs) "UTF-8"))
