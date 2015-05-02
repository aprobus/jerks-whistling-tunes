(ns jerks-whistling-tunes.sign
  (:require [byte-streams :refer [convert]]
            [crypto.equality :as cry]
            [jerks-whistling-tunes.utils :as utils])
  (:import java.security.KeyPair
           java.security.Signature
           java.security.SignatureException
           javax.crypto.Mac
           javax.crypto.spec.SecretKeySpec))

(def ^:private byte-array-class (Class/forName "[B"))

(defn- eq?
  "Compares two strings safely"
  [expected actual]
  (if (= "" actual expected)
    true
    (cry/eq? actual expected)))

(defn- sign*
  "Returns a string encoded with the specified algorithm and key"
  [crypto-alg private-key body]
  (let [body-bytes (convert body byte-array-class)
        signer (doto (Signature/getInstance crypto-alg)
                 (.initSign private-key)
                 (.update body-bytes))]
    (-> signer
      .sign
      utils/encode-base-64)))

(defn- valid-signature?*
  "Validates a signature using the public key"
  [crypto-alg public-key body signature]
  (let [body-bytes (convert body byte-array-class)
        signer (doto (Signature/getInstance crypto-alg)
                 (.initVerify public-key)
                 (.update body-bytes))
        raw-signature (utils/decode-base-64 signature)]
    (try
      (.verify signer raw-signature)
      (catch SignatureException e
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
    (let [body-bytes (convert body byte-array-class)
          encoder (doto (Mac/getInstance crypto-alg)
                    (.init secret-spec)
                    (.update body-bytes))]
      (utils/encode-base-64 (.doFinal encoder))))

  (valid-signature? [this body signature]
    (eq? (.sign this body) signature)))

(defrecord KeyPairAlg [alg crypto-alg public-key private-key]
  Algorithm
  (jwt-alg [this] alg)

  (sign [this body]
    (sign* crypto-alg private-key body))

  (valid-signature? [this body signature]
    (valid-signature?* crypto-alg public-key body signature)))

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
        secret-spec (SecretKeySpec. raw-secret jwt-alg)]
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

(defn- new-key-pair-alg [jwt-alg crypto-alg key]
  (if (instance? KeyPair key)
    (KeyPairAlg. jwt-alg crypto-alg (.getPublic key) (.getPrivate key))
    (KeyPairAlg. jwt-alg crypto-alg key nil)))

(def rs256
  "Returns a RS256 signer.
  If the key is a java.security.KeyPair, signing and verification will work.
  If the key is a public key, only verification will work."
  (partial new-key-pair-alg "RS256" "SHA256withRSA"))

(def rs384
  "Returns a RS384 signer.
  If the key is a java.security.KeyPair, signing and verification will work.
  If the key is a public key, only verification will work."
  (partial new-key-pair-alg "RS384" "SHA384withRSA"))

(def rs512
  "Returns a RS512 signer.
  If the key is a java.security.KeyPair, signing and verification will work.
  If the key is a public key, only verification will work."
  (partial new-key-pair-alg "RS512" "SHA512withRSA"))

(def ec256
  "Returns a EC256 signer.
  If the key is a java.security.KeyPair, signing and verification will work.
  If the key is a public key, only verification will work."
  (partial new-key-pair-alg "EC256" "SHA256withECDSA"))

(def ec384
  "Returns a EC384 signer.
  If the key is a java.security.KeyPair, signing and verification will work.
  If the key is a public key, only verification will work."
  (partial new-key-pair-alg "EC384" "SHA384withECDSA"))

(def ec512
  "Returns a EC512 signer.
  If the key is a java.security.KeyPair, signing and verification will work.
  If the key is a public key, only verification will work."
  (partial new-key-pair-alg "EC512" "SHA512withECDSA"))

(def none
  (None.))
