(ns jerks-whistling-tunes.core
  (:require [clojure.data.json :as json]
            [crypto.equality :refer [eq?]]))

(java.security.Security/addProvider
  (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(defmulti to-bytes type)
(defmethod to-bytes java.lang.String [str]
  (.getBytes str "UTF-8"))
(defmethod to-bytes (Class/forName "[B") [byte-array]
  byte-array)

(defn current-time-secs [] (int (/ (System/currentTimeMillis) 1000)))

(defn- first-arg [& args]
  (first args))

(def ^:private base-64 (org.apache.commons.codec.binary.Base64. true))
(defn decode-base-64 [str]
  (.decode base-64 str))
(defn- encode-base-64 [bytes]
  (let [result (String. (.encode base-64 bytes) "UTF-8")
        len-without-newline (- (count result) 2)]
    (.substring result 0 len-without-newline)))

(defmulti create-signature first-arg)
(defmethod create-signature "HS256" [_ secret body]
  (let [hmac-key (javax.crypto.spec.SecretKeySpec. (to-bytes secret) "HS256")
        encoder (doto (javax.crypto.Mac/getInstance "HmacSHA256")
                  (.init hmac-key)
                  (.update (.getBytes body "UTF-8")))]
    (encode-base-64 (.doFinal encoder))))

(defmulti verify (fn [& args] (first args)))
(defmethod verify "HS256" [_ secret body signature]
  (let [gen-sig (create-signature "HS256" secret body)]
    (eq? signature gen-sig)))
(defmethod verify :default [& args]
  false)

(defn- create-segment [segment]
  (let [json-str (json/write-str segment)]
    (encode-base-64 (.getBytes json-str "UTF-8"))))

(defn- parse-segment [segment]
  (-> segment
    decode-base-64
    (String. "UTF-8")
    (json/read-str :key-fn keyword)))

(defn- valid-signature? [{:keys [secret segments header]}]
  (let [[header-str claims-str sig-str] segments
        body (str header-str "." claims-str)]
    (verify (:alg header) secret body sig-str)))
(defn- valid-exp? [{:keys [claims]}]
  (if-let [exp-time (:exp claims)]
    (< (current-time-secs) exp-time)
    true))
(defn- valid-issuer? [{:keys [opts claims]}]
  (if-let [issuer (:iss opts)]
    (= issuer (:iss claims))
    true))
(defn- valid-audience? [{:keys [opts claims]}]
  (if-let [audience (:aud opts)]
    (= audience (:aud claims))
    true))

(defn- validate* [secret [header-str claims-str :as segments] opts]
  (let [claims (parse-segment claims-str)
        header (parse-segment header-str)
        secret ((get opts :secret-fn identity) secret)
        valid-token? ((every-pred valid-signature? valid-exp? valid-audience? valid-issuer?)
                      {:secret secret
                       :segments segments
                       :header header
                       :claims claims
                       :opts opts})]
    (if valid-token?
      claims
      false)))

(defn validate [secret token & more]
  (if-not (nil? token)
    (let [segments (clojure.string/split token #"\." 4)
          opts (apply hash-map more)]
      (if (= 3 (count segments))
        (validate* secret segments opts)
        false))
    false))

(def valid? (comp boolean validate))

(defn sign [alg secret claims & more]
  (let [header {:alg alg
                :typ "JWT"}
        body (str (create-segment header) "." (create-segment claims))
        opts (apply hash-map more)
        secret ((get opts :secret-fn identity) secret)
        signature (create-signature alg secret body)]
    (str body "." signature)))
