(ns jerks-whistling-tunes.core
  (:require [clojure.data.json :as json]
            [crypto.equality :refer [eq?]]))

(java.security.Security/addProvider
 (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(def base-64 (org.apache.commons.codec.binary.Base64. true))
(defn- decode-64 [str]
  (.decode base-64 str))

(defmulti sign (fn [& args] (first args)))
(defmethod sign "HS256" [_ secret body]
  (let [hmac-key (javax.crypto.spec.SecretKeySpec. (.getBytes secret "UTF-8") "HS256")
        encoder (doto (javax.crypto.Mac/getInstance "HmacSHA256")
                  (.init hmac-key)
                  (.update (.getBytes body "UTF-8")))
        signature (String. (.encode base-64 (.doFinal encoder)) "UTF-8")
        adjusted-length (- (count signature) 2)]
    (.substring signature 0 adjusted-length)))

(defmulti verify (fn [& args] (first args)))
(defmethod verify "HS256" [_ secret body signature]
  (let [gen-sig (sign "HS256" secret body)]
    (eq? signature gen-sig)))

(defn- parse-segment [segment]
  (-> segment
    decode-64
    (String. "UTF-8")
    (json/read-str :key-fn keyword)))

(defn valid? [secret token]
  (let [[header-str claims-str sig-str :as segments] (clojure.string/split token #"\." 4)]
    (if (= 3 (count segments))
      (let [header (parse-segment header-str)
            body (str header-str "." claims-str)]
        (verify (:alg header) secret body sig-str))
      false)))
