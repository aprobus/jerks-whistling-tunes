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

(defn- valid-signature? [{:keys [sign-fn segments header]}]
  (let [[header-str claims-str sig-str] segments
        body (str header-str "." claims-str)]
    (eq? (sign-fn body) sig-str)))

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

(defn- validate* [sign-fn [header-str claims-str :as segments] opts]
  (let [claims (parse-segment claims-str)
        header (parse-segment header-str)
        valid-token? ((every-pred valid-signature? valid-exp? valid-audience? valid-issuer?)
                      {:sign-fn sign-fn
                       :segments segments
                       :header header
                       :claims claims
                       :opts opts})]
    (if valid-token?
      claims
      false)))

(defn validate [sign-fn token & more]
  (if-not (nil? token)
    (let [segments (clojure.string/split token #"\." 4)
          opts (apply hash-map more)]
      (if (= 3 (count segments))
        (validate* sign-fn segments opts)
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
