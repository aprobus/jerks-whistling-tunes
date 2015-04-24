(ns jerks-whistling-tunes.sign
  (:require [byte-streams :refer [convert]]
            [jerks-whistling-tunes.utils :as utils]))

(def ^:private byte-array-class (Class/forName "[B"))

(defn- encode-str
  "Returns a string encoded with the specified HMAC algorithm and key."
  [instance-type secret-spec str]
  (let [str-bytes (convert str byte-array-class)
        encoder (doto (javax.crypto.Mac/getInstance instance-type)
                  (.init secret-spec)
                  (.update str-bytes))]
    (utils/encode-base-64 (.doFinal encoder))))

(defn- create-hmac-signer
  "Returns a function that performs HMAC signing."
  [secret-type instance-type secret]
  (let [raw-secret (convert secret byte-array-class)
        secret-spec (javax.crypto.spec.SecretKeySpec. raw-secret secret-type)
        sign-fn (partial encode-str instance-type secret-spec)]
    (with-meta sign-fn {:alg secret-type})))

(def hs256
  "Returns a function that performs HS256 signing with the specified key"
  (partial create-hmac-signer "HS256" "HmacSHA256"))

(def hs384
  "Returns a function that performs HS384 signing with the specified key"
  (partial create-hmac-signer "HS384" "HmacSHA384"))

(def hs512
  "Returns a function that performs HS512 signing with the specified key"
  (partial create-hmac-signer "HS512" "HmacSHA512"))

(def none
  "Signs a string with empty string"
  (with-meta (constantly "")
             {:alg "none"}))