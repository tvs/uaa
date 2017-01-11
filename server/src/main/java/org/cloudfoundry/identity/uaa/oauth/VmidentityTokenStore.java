/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2017] VMware, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;

public class VmidentityTokenStore implements AuthorizationCodeServices {
    public static final long EXPIRATION_TIME = 5 * 60 * 1000;

    protected static Log logger = LogFactory.getLog(VmidentityTokenStore.class);

    private final long expirationTime;
    private final RandomValueStringGenerator generator = new RandomValueStringGenerator(10);

    private final AtomicLong lastClean = new AtomicLong(0);

    private final ConcurrentHashMap<String, TokenCode> _codes;

    public VmidentityTokenStore() {
        this(EXPIRATION_TIME);
    }

    public VmidentityTokenStore(long expirationTime) {
        this.expirationTime = expirationTime;
        this._codes = new ConcurrentHashMap<String, TokenCode>();
    }

    @Override
    public String createAuthorizationCode(OAuth2Authentication authentication) {
        performExpirationClean();
        String code = generator.generate();
        long created = System.currentTimeMillis();
        long expiresAt = created + getExpirationTime();
        String userId = authentication.getUserAuthentication() == null ? null : ((UaaPrincipal) authentication.getUserAuthentication().getPrincipal()).getId();
        String clientId = authentication.getOAuth2Request().getClientId();

        TokenCode tc = new TokenCode(code, userId, clientId, expiresAt, created, authentication);
        this._codes.put(code, tc);
        return code;
    }

    @Override
    public OAuth2Authentication consumeAuthorizationCode(String code) throws InvalidGrantException {
        performExpirationClean();

        TokenCode tokenCode = this._codes.get(code);
        if (tokenCode != null) {
            this._codes.remove(code);
            if (tokenCode.isExpired()) {
                logger.debug("[oauth_code] Found code, but it expired:" + tokenCode);
                throw new InvalidGrantException("Authorization code expired: " + code);
            } else {
                return tokenCode.getAuthentication();
            }
        } else {
            throw new InvalidGrantException("Invalid authorization code: " + code);
        }
    }

    protected void performExpirationClean() {
        long last = lastClean.get();
        // check if we should expire again
        if ((System.currentTimeMillis() - last) > getExpirationTime()) {
            // avoid concurrent deletes from the same UAA - performance improvement
            if (lastClean.compareAndSet(last, last + getExpirationTime())) {

                ArrayList<TokenCode> toDelete = new ArrayList<TokenCode>();
                for (TokenCode tc : this._codes.values()) {
                    if (tc.isExpired()) {
                        toDelete.add(tc);
                    }
                }
                logger.debug(String.format("[oauth_code] Removing '%d' expired entries.", toDelete.size()));
                for (TokenCode tc : toDelete) {
                    this._codes.remove(tc.code);
                }
            }
        }

    }

    public long getExpirationTime() {
        return expirationTime;
    }

    private static class TokenCode {
        private final String code;
        private final String userId;
        private final String clientId;
        private final long expiresAt;
        private final long created;
        private final OAuth2Authentication authentication;

        public TokenCode(String code, String userId, String clientId, long expiresAt, long created,
                OAuth2Authentication authentication) {
            this.code = code;
            this.userId = userId;
            this.clientId = clientId;
            this.expiresAt = expiresAt;
            this.created = created;
            this.authentication = authentication;
        }

        public OAuth2Authentication getAuthentication() {
            return authentication;
        }

        public String getClientId() {
            return clientId;
        }

        public String getCode() {
            return code;
        }

        public long getCreated() {
            return created;
        }

        public long getExpiresAt() {
            return expiresAt;
        }

        public String getUserId() {
            return userId;
        }

        public boolean isExpired() {
            return getExpiresAt() < System.currentTimeMillis();
        }

        @Override
        public String toString() {
            return "TokenCode{" +
                    ", code='" + code + '\'' +
                    ", userId='" + userId + '\'' +
                    ", clientId='" + clientId + '\'' +
                    ", expiresAt=" + expiresAt +
                    ", created=" + created +
                    '}';
        }
    }
}