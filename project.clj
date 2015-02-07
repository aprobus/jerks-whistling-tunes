(defproject jerks-whistling-tunes "0.1.1"
  :description "Clojure library for creating/verifying JWT"
  :url "https://github.com/aprobus/jerks-whistling-tunes"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [org.clojure/data.json "0.2.5"]
                 [org.bouncycastle/bcprov-jdk15 "1.46"]
                 [crypto-equality "1.0.0"]
                 [commons-codec/commons-codec "1.9"]]
  :profiles {:dev {:dependencies [[speclj "2.5.0"]]}}
  :plugins [[speclj "2.5.0"]]
  :test-paths ["spec"])
