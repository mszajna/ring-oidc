(ns ring-oidc
  (:require [clj-jwt.core :as jwt])
  (:import java.time.Instant
           java.security.SignatureException
           [org.jose4j.jwk JsonWebKey
                           JsonWebKeySet]))

; TODO: handle badly formatted tokens, when claims are not the data type you'd expect
(defn id-token-validation-issues
  "Validates id-token map according to OpenID Connect rules defined in
   https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation.
   Returns a list of issues or nil if valid. Options:
   - issuer - required,
   - client-id - required,
   - tls-validated? - indicates Authorization Code Flow and skips signature,
     validation, defaults to false,
   - algorithm - defaults to :RS256,,
   - client-secret - required to validate signature when algorithm is MAC based,
   - key-fn - required when algorithm is non-MAC based, takes JWT header and
     returns a PublicKey,
   - trusted-aud-pred - used to verify additional audiences outside client-id,
     defaults to rejecting all,
   - max-age - used to reject tokens issued too long ago, defaults to accepting
     all,
   - nonce - required in Implicit and Hybrid Flow."
  [id-token
   {:keys [issuer
           client-id
           algorithm
           client-secret
           key-fn
           tls-validated?
           trusted-aud-pred
           max-age
           nonce]
    :or {algorithm :RS256}
    :as opts}]
  (let [{{:keys [alg enc] :as header} :header
         {token-nonce :nonce :keys [exp iat iss aud]} :claims}
        id-token

        now
        (.getEpochSecond (Instant/now))

        issues
        [ ; 3.1.3.7. 1
          ; Not implemented - decryption is outside of the scope

          ; 3.1.3.7. 2
          (when-not (= iss issuer)
            ::iss-mismatch)

          ; 3.1.3.7. 3
          (when-not (if (coll? aud)
                      (some #(= % client-id) aud)
                      (= aud client-id))
            ::aud-mismatch)
          (when (and (coll? aud)
                    (some #(= % client-id) aud)
                    (not-every? #(or (= % client-id)
                                      (and trusted-aud-pred
                                          (trusted-aud-pred %)))
                                aud))
            ::aud-distrusted)

          ; 3.1.3.7. 4
          (when (and (coll? aud) (nil? azp))
            ::multi-aud-no-azp)

          ; 3.1.3.7. 5
          (when (and azp (not= azp client-id))
            ::azp-mismatch)

          ; 3.1.3.7. 6, 7 & 8
          (when-not tls-validated?
            (if-not (= alg algorithm) ; 3.1.3.7. 7
              ::alg-mismatch
              (if-let [key (if (#{:HS256 :HS384 :HS512} alg)
                            client-secret ; 3.1.3.7. 8
                            (and key-fn (key-fn header)))]
                (when-not (try (jwt/verify jwt key) (catch SignatureException _ false))
                  ::bad-signature)
                ::no-matching-key-found)))

          ; 3.1.3.7. 9
          (when (<= exp now)
            ::expired)

          ; 3.1.3.7. 10
          (when (and max-age (<= (+ iat max-age) now))
            ::iat-too-long-ago)

          ; 3.1.3.7. 11
          (when (and nonce (not= nonce token-nonce))
            ::nonce-mismatch)]]

    (seq (remove nil? issues))))

(defn valid-id-token+issues
  [id-token-str opts]
  (if-let [id-token (try (jwt/str->jwt token) (catch Exception _ nil))]
    (if-let [issues (id-token-validation-issues id-token opts)]
      [nil issues]
      [id-token])
    [nil '(::not-parsable-jwt)]))

(defn bearer-token [request]
  (if-let [authorization (get-in request [:headers "authorization"])]
    (when (re-find #"(?i)bearer\s" authorization)
      (subs authorization 7))))

(defn oidc-claims-request [request oidc-config]
  (if-let [token (bearer-token request)]
    (if-let [id-token (try (jwt/str->jwt token) (catch Exception _ nil))]
      (if-let [issues (id-token-validation-issues id-token oidc-config)]
        (assoc request ::issues issues)
        (assoc request :identity (:claims id-token)))
      (assoc request ::issues [::bearer-token-not-jwt]))
    request))

; TODO: check if all these type hints are actually needed
(defn- ->JsonWebKeySet [{keys "keys"}]
  (assert (seq keys) "Expected 'keys' not to be empty")
  (let [jwks (map #(JsonWebKey$Factory/newJwk ^Map %) keys)]
    (new JsonWebKeySet ^List jwks)))

(defn- find-sig-key [^JsonWebKeySet jwks {:keys [kid alg]}]
  (if-let [sig-key (.findJsonWebKey jwks kid nil "sig" alg)]
    (.getPublicKey sig-key)))

(defn jwks-key [jwks-map]
  (partial find-sig-key (->JsonWebKeySet jwks-map)))

(defn jwks-str-key [^String jwks-str]
  (partial find-sig-key (new JsonWebKeySet jwks-str)))

(defn wrap-oidc-claims
  [handler oidc-config]
  (fn
    ([request]
      (handler (oidc-claims-request request oidc-config)))
    ([request respond raise]
      (handler (oidc-claims-request request oidc-config) respond raise))))
