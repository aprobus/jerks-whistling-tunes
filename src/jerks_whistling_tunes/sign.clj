(ns jerks-whistling-tunes.sign
  (:require [byte-streams :refer [convert]]
            [crypto.equality :as cry]
            [jerks-whistling-tunes.utils :as utils]))

(def ^:private byte-array-class (Class/forName "[B"))

(defn- eq?
  "Compares two strings safely"
  [expected actual]
  (if (= "" actual expected)
    true
    (cry/eq? actual expected)))

(defn- sign-hmac
  "Returns a string encoded with the specified HMAC algorithm and key"
  [crypto-alg secret-spec body]
  (let [body-bytes (convert body byte-array-class)
        encoder (doto (javax.crypto.Mac/getInstance crypto-alg)
                  (.init secret-spec)
                  (.update body-bytes))]
    (utils/encode-base-64 (.doFinal encoder))))

(defn- sign-rsa
  "Returns a string encoded with the specified RSA algorithm and key"
  [crypto-alg private-key body]
  (let [body-bytes (convert body byte-array-class)
        signer (doto (java.security.Signature/getInstance crypto-alg)
                 (.initSign private-key)
                 (.update body-bytes))]
    (-> signer
      .sign
      utils/encode-base-64)))

(defn- valid-rsa-signature?
  "Validates an rsa signature"
  [crypto-alg public-key body signature]
  (let [body-bytes (convert body byte-array-class)
        signer (doto (java.security.Signature/getInstance crypto-alg)
                 (.initVerify public-key)
                 (.update body-bytes))
        raw-signature (utils/decode-base-64 signature)]
    (try
      (.verify signer raw-signature)
      (catch java.security.SignatureException e
        false))))

(defprotocol Algorithm
  (jwt-alg [this]
           "The jwt algorithm implemented")
  (sign [this body]
        "Returns a base 64 encoded signature of the body")
  (valid-signature? [this body signature]
                    "Returns true if the signature is valid for the body, false otherwise"))

(defrecord Hmac [alg crypto-alg secret-spec]
  Algorithm
  (jwt-alg [this] alg)

  (sign [this body]
    (sign-hmac crypto-alg secret-spec body))

  (valid-signature? [this body signature]
    (eq? (.sign this body) signature)))

(defrecord Rsa [alg crypto-alg public-key private-key]
  Algorithm
  (jwt-alg [this] alg)

  (sign [this body]
    (sign-rsa crypto-alg private-key body))

  (valid-signature? [this body signature]
    (valid-rsa-signature? crypto-alg public-key body signature)))

(defrecord None []
  Algorithm
  (jwt-alg [this] "none")

  (sign [this body]
    "")

  (valid-signature? [this body signature]
    (= "" signature)))

(defn- new-hmac
  [jwt-alg crypto-alg secret]
  (let [raw-secret (convert secret byte-array-class)
        secret-spec (javax.crypto.spec.SecretKeySpec. raw-secret jwt-alg)]
    (Hmac. jwt-alg crypto-alg secret-spec)))

(def hs256
  "Returns a HS256 signer"
  (partial new-hmac "HS256" "HmacSHA256"))

(def hs384
  "Returns a HS384 signer"
  (partial new-hmac "HS384" "HmacSHA384"))

(def hs512
  "Returns a HS512 signer"
  (partial new-hmac "HS512" "HmacSHA512"))

(defn- new-rsa [jwt-alg crypto-alg key]
  (if (instance? java.security.KeyPair key)
    (Rsa. jwt-alg crypto-alg (.getPublic key) (.getPrivate key))
    (Rsa. jwt-alg crypto-alg key nil)))

(def rs256
  "Returns a RS256 signer.
  If the key is a java.security.KeyPair, signing and verification will work.
  If the key is a public key, only verification will work."
  (partial new-rsa "RS256" "SHA256withRSA"))

(def rs384
  "Returns a RS384 signer.
  If the key is a java.security.KeyPair, signing and verification will work.
  If the key is a public key, only verification will work."
  (partial new-rsa "RS384" "SHA384withRSA"))

(def rs512
  "Returns a RS512 signer.
  If the key is a java.security.KeyPair, signing and verification will work.
  If the key is a public key, only verification will work."
  (partial new-rsa "RS512" "SHA512withRSA"))

(def none
  (None.))
