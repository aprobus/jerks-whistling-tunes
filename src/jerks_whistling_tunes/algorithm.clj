(ns jerks-whistling-tunes.algorithm
  (:require [byte-streams :refer [convert]]
            [jerks-whistling-tunes.utils :as utils]))

(def ^:private byte-array-class (Class/forName "[B"))

(defn hs256 [secret]
  (let [secret-bytes (convert secret byte-array-class)
        hmac-key (javax.crypto.spec.SecretKeySpec. secret-bytes "HS256")]
    (fn [body]
      (let [body-bytes (convert body byte-array-class)
            encoder (doto (javax.crypto.Mac/getInstance "HmacSHA256")
                      (.init hmac-key)
                      (.update body-bytes))]
        (utils/encode-base-64 (.doFinal encoder))))))
