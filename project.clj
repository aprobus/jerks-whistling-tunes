(defproject jerks-whistling-tunes "0.3.0"
  :description "Clojure library for creating/verifying JWT"
  :url "https://github.com/aprobus/jerks-whistling-tunes"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [org.clojure/data.json "0.2.6"]
                 [org.bouncycastle/bcprov-jdk15on "1.56"]
                 [byte-streams "0.2.2"]
                 [crypto-equality "1.0.0"]
                 [commons-codec/commons-codec "1.10"]]
  :profiles {:dev {:dependencies [[speclj "3.3.2"]
                                  [org.bouncycastle/bcpkix-jdk15on "1.56"]]
                   :global-vars {*warn-on-reflection* true}}}
  :repositories [["releases" {:url "https://clojars.org/repo"
                              :sign-releases false }]]
  :plugins [[speclj "3.3.2"]]
  :test-paths ["spec"])
