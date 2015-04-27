(ns jerks-whistling-tunes.core
  (:require [clojure.data.json :as json]
            [clojure.string :as string]
            [crypto.equality :as cry]
            [jerks-whistling-tunes.utils :as utils]))

(java.security.Security/addProvider
  (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(defn current-time-secs
  "Returns the current time in seconds"
  []
  (int (/ (System/currentTimeMillis) 1000)))

(defn- create-segment
  "Returns the base 64 encoded JSON representation"
  [segment]
  (-> segment
    json/write-str
    (.getBytes "UTF-8")
    (utils/encode-base-64)))

(defn- parse-segment
  "Takes a base 64 encoded string and returns the parsed JSON representation"
  [segment]
  (try
    (-> segment
      utils/decode-base-64
      (String. "UTF-8")
      (json/read-str :key-fn keyword))
    (catch Exception e nil)))

(defn- validate*
  "Parses JWT segments and validates them against a collection of predicates.
  Returns true if all the validation checks returned true, false otherwise."
  [[header-str claims-str token-signature] validation-fns]
  (let [claims (parse-segment claims-str)
        header (parse-segment header-str)
        valid-claims? (apply every-pred (constantly true) validation-fns)]
    (if (and claims header (valid-claims? header claims [(str header-str "." claims-str) token-signature]))
      claims
      false)))

(defn validate
  "Validates a JWT against a collection of predicates.
  If the token is valid, validate returns the claims.
  Otherwise validate returns false"
  [token & validation-fns]
  (if-not (nil? token)
    (let [segments (string/split token #"\." 4)]
      (if (= 3 (count segments))
        (validate* segments validation-fns)
        false))
    false))

(def valid?
  "Validates a JWT against a collection of predicates.
  Returns true if all the predicates are successful, false otherwise"
  (comp boolean validate))

(defn encode
  "Encodes a map of claims as a JWT."
  [claims signer]
  (let [header {:alg (.alg signer)
                :typ "JWT"}
        body (str (create-segment header) "." (create-segment claims))
        signature (.sign signer body)]
    (str body "." signature)))

(defn aud
  "Returns a predicate that validates the aud of a JWT"
  [expected-aud]
  (fn [_ {:keys [aud]} _]
    (= aud expected-aud)))

(defn iss
  "Returns a predicate that validates the iss of a JWT"
  [expected-iss]
  (fn [_ {:keys [iss]} _]
    (= iss expected-iss)))

(defn sub
  "Returns a predicate that validates the sub of a JWT"
  [expected-sub]
  (fn [_ {:keys [sub]} _]
    (= sub expected-sub)))

(defn exp
  "Returns true if the JWT has not expired, false otherwise"
  [_ {:keys [exp]} _]
  (and (number? exp)
       (>= exp (current-time-secs))))

(defn nbf
  "Returns true if the nbf time has passed, false otherwise"
  [_ {:keys [nbf]} _]
  (and (number? nbf)
       (>= (current-time-secs) nbf)))

(defn iat
  "Returns true if the JWT was issued in the past, false otherwise"
  [_ {:keys [iat]} _]
  (and (number? iat)
       (<= iat (current-time-secs))))

(defn- safe-map-sign-fns
  "Takes a collection of signature functions and returns a map of the algorithm to the function."
  [signers]
  (reduce (fn [acc signer]
            (let [alg (.alg signer)]
              (if (contains? acc alg)
                (throw (Exception. (str "Duplicate algorithms not supported: " alg)))
                (assoc acc
                       alg
                       signer))))
          {}
          signers))

(defn signature
  "Returns a predicate that validates the signature of a JWT.
  sign-fns should have an alg specified in the metadata.
  The algorithm is picked based on the alg field in the header"
  [& sign-fns]
  (let [sign-map (safe-map-sign-fns sign-fns)]
    (fn [{:keys [alg]} _ [header-str claims-str token-signature]]
      (if-let [signer (get sign-map alg)]
        (.valid-signature? signer (str header-str "." claims-str) token-signature)
        false))))
