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
  (try (-> segment
         utils/decode-base-64
         (String. "UTF-8")
         (json/read-str :key-fn keyword))
       (catch Exception e nil)))

(defn- eq? [expected actual]
  (if (= "" actual expected)
    true
    (cry/eq? actual expected)))

(defn- validate* [[header-str claims-str token-signature] validation-fns]
  (let [claims (parse-segment claims-str)
        header (parse-segment header-str)
        valid-claims? (apply every-pred (constantly true) validation-fns)]
    (if (and claims header (valid-claims? header claims [(str header-str "." claims-str) token-signature]))
      claims
      false)))

(defn validate [token & validation-fns]
  (if-not (nil? token)
    (let [segments (clojure.string/split token #"\." 4)]
      (if (= 3 (count segments))
        (validate* segments validation-fns)
        false))
    false))

(def valid? (comp boolean validate))

(defn encode [claims sign-fn]
  (let [{:keys [alg]} (meta sign-fn)
        header {:alg alg
                :typ "JWT"}
        body (str (create-segment header) "." (create-segment claims))
        signature (sign-fn body)]
    (str body "." signature)))

(defn aud [expected-aud]
  (fn [_ {:keys [aud]} _]
    (= aud expected-aud)))

(defn iss [expected-iss]
  (fn [_ {:keys [iss]} _]
    (= iss expected-iss)))

(defn sub [expected-sub]
  (fn [_ {:keys [sub]} _]
    (= sub expected-sub)))

(defn exp [_ {:keys [exp]} _]
  (if exp
    (>= exp (current-time-secs))
    false))

(defn nbf [_ {:keys [nbf]} _]
  (if nbf
    (>= (current-time-secs) nbf)
    false))

(defn iat [_ {:keys [iat]} _]
  (if iat
    (<= iat (current-time-secs))
    false))

(defn- safe-map-sign-fns [sign-fns]
  (reduce (fn [acc sign-fn]
            (let [{:keys [alg]} (meta sign-fn)]
              (if (contains? acc alg)
                (throw (Exception. (str "Duplicate algorithms not supported: " alg)))
                (assoc acc
                       alg
                       sign-fn))))
          {}
          sign-fns))

(defn signature [& sign-fns]
  (let [sign-map (safe-map-sign-fns sign-fns)]
    (fn [{:keys [alg]} _ [header-str claims-str token-signature]]
      (if-let [signer-fn (get sign-map alg)]
        (eq? token-signature (signer-fn (str header-str "." claims-str)))
        false))))
