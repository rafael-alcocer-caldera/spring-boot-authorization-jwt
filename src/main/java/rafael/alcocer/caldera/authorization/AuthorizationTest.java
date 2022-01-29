/**
 * Copyright [2022] [RAFAEL ALCOCER CALDERA]
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package rafael.alcocer.caldera.authorization;

import java.util.Date;
import java.util.HashMap;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import rafael.alcocer.caldera.authorization.utils.Utils;

public class AuthorizationTest {

    public static void main(String[] args) {
        AuthorizationTest authorizationTest = new AuthorizationTest();
        authorizationTest.go2();

        //testCreateJWT();
        //testParseJWT();
    }

    /**
     * Secret Keys
     * 
     * If you want to generate a sufficiently strong SecretKey for use with the JWT
     * HMAC-SHA algorithms, use the Keys.secretKeyFor(SignatureAlgorithm) helper
     * method:
     * 
     * SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256); //or HS384 or
     * HS512
     * 
     * Under the hood, JJWT uses the JCA provider's KeyGenerator to create a
     * secure-random key with the correct minimum length for the given algorithm.
     * 
     * If you need to save this new SecretKey, you can Base64 (or Base64URL) encode
     * it:
     * 
     * String secretString = Encoders.BASE64.encode(key.getEncoded());
     * 
     * Ensure you save the resulting secretString somewhere safe - Base64-encoding
     * is not encryption, so it's still considered sensitive information. You can
     * further encrypt it, etc, before saving to disk (for example).
     */
    public void go() {
        // We need a signing key, so we'll create one just for this example. Usually
        // the key would be read from your application configuration instead.
        /*
         * Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
         * System.out.println("##### key:  " + key);
         * System.out.println("##### key.getAlgorithm():  " + key.getAlgorithm());
         * System.out.println("##### key.getFormat():  " + key.getFormat());
         * System.out.println("##### key.serialVersionUID:  " + key.serialVersionUID);
         * System.out.println();
         * 
         * String secretString = Encoders.BASE64.encode(key.getEncoded());
         * System.out.println("##### secretString:  " + secretString);
         * System.out.println();
         * 
         * String jws =
         * Jwts.builder().setIssuer("rapidshop").setSubject("RAC").signWith(key).compact
         * (); System.out.println("##### jws:  " + jws);
         * 
         * System.out.println(Jwts.parserBuilder().setSigningKey(key).build().
         * parseClaimsJws(jws).getBody().getSubject() .equals("RAC"));
         */

        /*
        Key key = Utils.generateSecretKey();

        String secretString = Utils.generateSecretKeyToBeSaved(key);
        System.out.println("##### secretString: " + secretString);

        String JWT = Utils.generateJwt(key);
        System.out.println("##### JWT: " + JWT);

        String x = Jwts.builder().setIssuer("rapidshop").setSubject("RAC")
                .signWith(SignatureAlgorithm.HS256, secretString).compact();

        System.out.println("##### x: " + x);

        byte[] byteFromSecret = Utils.retriveSecretKeyFromEncodedBase64(secretString);

        System.out.println("##### byteFromSecret: " + byteFromSecret);

        System.out.println("##### Compare Arrays: " + Arrays.equals(key.getEncoded(), byteFromSecret));
        
        SecretKey keyByteFromSecret = Keys.hmacShaKeyFor(byteFromSecret);
        System.out.println("##### keyByteFromSecret: " + keyByteFromSecret);
        
        SecretKey keyEncoded = Keys.hmacShaKeyFor(key.getEncoded());
        System.out.println("##### keyEncoded: " + keyEncoded);
        
        SecretKey secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretString));
        System.out.println("##### secretKey 2: " + secretKey);
        */

        /*
         * If your secret key is:
         * 
         * An encoded byte array:
         * ----------------------
         * SecretKey key = Keys.hmacShaKeyFor(encodedKeyBytes); 
         * 
         * A Base64-encoded string:
         * ------------------------
         * SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretString)); 
         * 
         * A Base64URL-encoded string:
         * ---------------------------
         * SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretString));
         * 
         * A raw (non-encoded) string (e.g. a password String):
         * ----------------------------------------------------
         * SecretKey key =
         * Keys.hmacShaKeyFor(secretString.getBytes(StandardCharsets.UTF_8));
         */
    }

    public static void testCreateJWT() {
        JwtBuilder builder = Jwts.builder().setId("404") // Set unique number
                .setSubject("Xing Libao") // The setting theme can be JSON data
                .setIssuedAt(new Date()) // Set issue date
                // . setExpiration(new Date()) / / set expiration time
                // Set the signature to use HS256 algorithm and set the secretkey (string)
                .signWith(SignatureAlgorithm.HS256, "PdcMjFgdtTn4MN0gTTOJmM6RTnFFhrr7ogjcB5UKuYk=");

        HashMap<String, Object> userInfo = new HashMap<>();
        userInfo.put("name", "When can dead trees spring");
        userInfo.put("age", "21");
        builder.addClaims(userInfo);

        System.out.println("##### JwtBuilder: " + builder.compact());
    }

    public static void testParseJWT() {
        String str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJyYXBpZHNob3AiLCJzdWIiOiJSQUMifQ.Zd9eif3bY6FEkfLu06s9C8xFogRzvC_2GoH6xqnl0qk";

        try {
            Claims claims = Jwts.parser().setSigningKey("PdcMjFgdtTn4MN0gTTOJmM6RTnFFhrr7ogjcB5UKuYk=")
                    .parseClaimsJws(str).getBody();

            System.out.println("##### Claims: " + claims);
        } catch (JwtException e) {
            // Don't trust the JWT!
            System.out.println("#####  Don't trust the JWT!: " + e.getMessage());
        }
    }
    
    public void go2() {
        SecretKey secretKey1 = Utils.generateSecretKey(SignatureAlgorithm.HS256);
        System.out.println("##### secretKey1: " + secretKey1);
        
        String secretKeyString1 = Utils.generateSecretKeyToBeSaved(secretKey1);
        System.out.println("##### secretKeyString1: " + secretKeyString1);
        
        Date expirationAdded10Mins = Utils.getDatePlusMinutesAdded(10);
        
        String jwt1 = Utils.generateJWT(secretKey1, "1", "rapidshop", "MySubject1", expirationAdded10Mins);
        System.out.println("##### JWT1: " + jwt1);
        
        SecretKey secretKey2 = Utils.getSecretKeyFromEncodedBase64String(secretKeyString1);
        System.out.println("##### secretKey2: " + secretKey2);
        
        String secretKeyString2 = Utils.generateSecretKeyToBeSaved(secretKey2);
        System.out.println("##### secretKeyString2: " + secretKeyString2);
        
        Jws<Claims> claims1 = Utils.verifyJWT(secretKey1, jwt1);
        System.out.println("##### claims1.getHeader(): " + claims1.getHeader());
        System.out.println("##### claims1.getBody(): " + claims1.getBody());
        System.out.println("##### claims1.getSignature(): " + claims1.getSignature());
        
        Jws<Claims> claims2 = Utils.verifyJWT(secretKey2, jwt1);
        System.out.println("##### claims2.getHeader(): " + claims2.getHeader());
        System.out.println("##### claims2.getBody(): " + claims2.getBody());
        System.out.println("##### claims2.getSignature(): " + claims2.getSignature());
        
        String secretKeyString3 = "CZ2rQAHY+8+JEYud0MNgdpWk66zfqgoc+5G0oafcCJI=";
        System.out.println("##### secretKeyString3: " + secretKeyString3);
        
        SecretKey secretKey3 = Utils.getSecretKeyFromEncodedBase64String(secretKeyString3);
        System.out.println("##### secretKey3: " + secretKey3);
        
        String jwt3 = Utils.generateJWT(secretKey3, "3", "rapidshop", "MySubject3", expirationAdded10Mins);
        System.out.println("##### JWT3: " + jwt3);
        
        Jws<Claims> claims3 = Utils.verifyJWT(secretKey3, jwt3);
        System.out.println("##### claims3.getHeader(): " + claims3.getHeader());
        System.out.println("##### claims3.getBody(): " + claims3.getBody());
        System.out.println("##### claims3.getSignature(): " + claims3.getSignature());
        
        Jws<Claims> claims4 = Utils.verifyJWT(secretKey1, jwt3);
        System.out.println("##### claims4.getHeader(): " + claims4.getHeader());
        System.out.println("##### claims4.getBody(): " + claims4.getBody());
        System.out.println("##### claims4.getSignature(): " + claims4.getSignature());
    }
}