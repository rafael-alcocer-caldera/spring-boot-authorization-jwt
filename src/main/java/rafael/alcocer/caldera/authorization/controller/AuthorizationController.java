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
package rafael.alcocer.caldera.authorization.controller;

import java.util.Date;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import rafael.alcocer.caldera.authorization.configuration.WebSecurityConfiguration;
import rafael.alcocer.caldera.authorization.model.User;
import rafael.alcocer.caldera.authorization.payload.request.AuthorizationRequest;
import rafael.alcocer.caldera.authorization.utils.Utils;

@RequiredArgsConstructor
@RestController
public class AuthorizationController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationController.class);
    private final WebSecurityConfiguration webSecurityConfiguration;

    @PostMapping("authorization")
    public ResponseEntity<?> login(@RequestBody AuthorizationRequest request) {
        LOGGER.info("##### username: " + request.getUsername());
        LOGGER.info("##### password: " + request.getPassword());
        LOGGER.info("##### webSecurityConfiguration.getSecretKey(): " + webSecurityConfiguration.getSecretKey());

        /*
         * **************************************************************************
         * 
         * HERE IS THE PLACE WHERE YOU SHOULD ACCESS TO THE DATABASE AND CHECK IF THE
         * USER IS VALID, IN THIS CASE CONTINUE WITH THE NEXT DECLARATIONS, OTHERWISE
         * RETURN A MESSAGE O AN EXCEPTION SAYING THAT THIS IS AN INVALID USER
         * 
         * **************************************************************************
         */

        SecretKey secretKey = Utils.getSecretKeyFromEncodedBase64String(webSecurityConfiguration.getSecretKey());

        Date dateTime = Utils.getDatePlusMinutesAdded(webSecurityConfiguration.getMinutes());
        LOGGER.info("##### dateTime (including minutes added: " + dateTime);

        String jwt = Utils.generateJWT(secretKey, Utils.generateUUID(), webSecurityConfiguration.getIssuer(),
                webSecurityConfiguration.getSubject(), dateTime);
        LOGGER.info("##### JWT: " + jwt);

        User user = new User();
        user.setUsername(request.getUsername());
        user.setJwt(jwt);

        return new ResponseEntity<>(user, HttpStatus.OK);
    }
}
