(ns jerks-whistling-tunes.core
  (:require [clojure.data.json :as json]
            [jerks-whistling-tunes.utils :as utils]
            [crypto.equality :as cry]))

(java.security.Security/addProvider
  (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(defn current-time-secs []
  (int (/ (System/currentTimeMillis) 1000)))

(defn- create-segment [segment]
  (let [json-str (json/write-str segment)]
    (utils/encode-base-64 (.getBytes json-str "UTF-8"))))

(defn- parse-segment [segment]
  (-> segment
    utils/decode-base-64
    (String. "UTF-8")
    (json/read-str :key-fn keyword)))

(defn- eq? [expected actual]
  (if (= "" actual expected)
    true
    (cry/eq? actual expected)))

(defn- valid-signature? [sign-fn segments header]
  (let [[header-str claims-str sig-str] segments
        body (str header-str "." claims-str)]
    (eq? (sign-fn body) sig-str)))

(defn- validate* [sign-fn [header-str claims-str :as segments] claim-fns]
  (let [claims (parse-segment claims-str)
        header (parse-segment header-str)
        valid-claims? (apply every-pred (constantly true) claim-fns)]
    (if (and (valid-signature? sign-fn segments header)
             (valid-claims? claims))
      claims
      false)))

(defn validate [sign-fn token & claim-fns]
  (if-not (nil? token)
    (let [segments (clojure.string/split token #"\." 4)]
      (if (= 3 (count segments))
        (validate* sign-fn segments claim-fns)
        false))
    false))

(def valid? (comp boolean validate))

(defn sign [claims sign-fn]
  (let [{:keys [alg]} (meta sign-fn)
        header {:alg alg
                :typ "JWT"}
        body (str (create-segment header) "." (create-segment claims))
        signature (sign-fn body)]
    (str body "." signature)))

(defn aud [expected-aud]
  (fn [{:keys [aud]}]
    (= aud expected-aud)))

(defn iss [expected-iss]
  (fn [{:keys [iss]}]
    (= iss expected-iss)))

(defn exp [{:keys [exp]}]
  (if exp
    (>= exp (current-time-secs))
    false))

(defn nbf [{:keys [nbf]}]
  (if nbf
    (>= (current-time-secs) nbf)
    false))
