(ns jerks-whistling-tunes.algorithm
  (:require [byte-streams :refer [convert]]
            [jerks-whistling-tunes.utils :as utils]))

(def ^:private byte-array-class (Class/forName "[B"))

(defn- create-hmac-signer [secret-type instance-type secret]
  (let [secret-bytes (convert secret byte-array-class)
        hmac-key (javax.crypto.spec.SecretKeySpec. secret-bytes secret-type)]
    (fn [body]
      (let [body-bytes (convert body byte-array-class)
            encoder (doto (javax.crypto.Mac/getInstance instance-type)
                      (.init hmac-key)
                      (.update body-bytes))]
        (utils/encode-base-64 (.doFinal encoder))))))

(def hs256 (partial create-hmac-signer "HS256" "HmacSHA256"))
(def hs384 (partial create-hmac-signer "HS384" "HmacSHA384"))
(def hs512 (partial create-hmac-signer "HS512" "HmacSHA512"))
