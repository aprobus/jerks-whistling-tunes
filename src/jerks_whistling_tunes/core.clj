(ns jerks-whistling-tunes.core
  (:require [clojure.data.json :as json]
            [crypto.equality :refer [eq?]]))

(java.security.Security/addProvider
 (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(defn- first-arg [& args]
  (first args))

(def ^:private base-64 (org.apache.commons.codec.binary.Base64. true))
(defn- decode-64 [str]
  (.decode base-64 str))
(defn- encode-64 [bytes]
  (let [result (String. (.encode base-64 bytes) "UTF-8")
        len-without-newline (- (count result) 2)]
    (.substring result 0 len-without-newline)))

(defmulti create-signature first-arg)
(defmethod create-signature "HS256" [_ secret body]
  (let [hmac-key (javax.crypto.spec.SecretKeySpec. (.getBytes secret "UTF-8") "HS256")
        encoder (doto (javax.crypto.Mac/getInstance "HmacSHA256")
                  (.init hmac-key)
                  (.update (.getBytes body "UTF-8")))]
    (encode-64 (.doFinal encoder))))

(defmulti verify (fn [& args] (first args)))
(defmethod verify "HS256" [_ secret body signature]
  (let [gen-sig (create-signature "HS256" secret body)]
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

(defn- create-segment [segment]
  (let [json-str (json/write-str segment)]
    (encode-64 (.getBytes json-str "UTF-8"))))

(defn sign [alg secret claims]
  (let [header {:alg alg
                :typ "JWT"}
        body (str (create-segment header) "." (create-segment claims))
        signature (create-signature alg secret body)]
    (str body "." signature)))
