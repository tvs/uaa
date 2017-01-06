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
package org.cloudfoundry.identity.uaa.oauth.token;

import static org.springframework.util.StringUtils.isEmpty;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.EmptyResultDataAccessException;

public class VmidentityRevocableTokenProvisioning implements RevocableTokenProvisioning, SystemDeletable {

    protected static final Log logger = LogFactory.getLog(VmidentityRevocableTokenProvisioning.class);

    private final ConcurrentHashMap<String, RevocableToken> _tokens;

    protected AtomicLong lastExpiredCheck = new AtomicLong(0);
    protected long expirationCheckInterval = 30000; // 30 seconds

    public VmidentityRevocableTokenProvisioning() {
        this._tokens = new ConcurrentHashMap<String, RevocableToken>();
    }

    @Override
    public List<RevocableToken> retrieveAll() {
        return null;
    }

    public RevocableToken retrieve(String id, boolean checkExpired) {
        if (checkExpired) {
            checkExpired();
        }
        RevocableToken result = this._tokens.get(id);
        if (result == null) {
            throw new EmptyResultDataAccessException("Token not found '" + id + "'.", 1);
        }
        if (checkExpired && result.getExpiresAt() < System.currentTimeMillis()) {
            delete(id, 0);
            throw new EmptyResultDataAccessException("Token expired.", 1);
        }
        return result;
    }

    @Override
    public RevocableToken retrieve(String id) {
        return retrieve(id, true);
    }

    @Override
    public RevocableToken create(RevocableToken t) {
        checkExpired();
        t.setZoneId(IdentityZoneHolder.get().getId());
        this._tokens.put(t.getTokenId(), t);
        return t;
    }

    @Override
    public RevocableToken update(String id, RevocableToken t) {
        t.setZoneId(IdentityZoneHolder.get().getId());
        this._tokens.put(t.getTokenId(), t);
        return t;
    }

    @Override
    public RevocableToken delete(String id, int version) {
        RevocableToken previous = this._tokens.get(id);
        if (previous != null) {
            this._tokens.remove(id);
        }
        return previous;
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        ArrayList<RevocableToken> toRemove = new ArrayList<RevocableToken>();
        for (RevocableToken t : this._tokens.values()) {
            if (IdentityZoneHolder.get().getId().equals(t.getZoneId())) {
                toRemove.add(t);
            }
        }
        for (RevocableToken t : toRemove) {
            this._tokens.remove(t.getTokenId());
        }
        return toRemove.size();
    }

    @Override
    public int deleteByOrigin(String origin, String zoneId) {
        return 0;
    }

    @Override
    public List<RevocableToken> getUserTokens(String userId) {
        ArrayList<RevocableToken> userTokens = new ArrayList<RevocableToken>();
        for (RevocableToken t : this._tokens.values()) {
            if (t.getUserId().equals(userId)) {
                userTokens.add(t);
            }
        }
        return userTokens;
    }

    @Override
    public List<RevocableToken> getUserTokens(String userId, String clientId) {
        if (isEmpty(clientId)) {
            throw new IllegalArgumentException("Client ID can not be null when retrieving tokens.");
        }
        ArrayList<RevocableToken> userTokens = new ArrayList<RevocableToken>();
        for (RevocableToken t : this._tokens.values()) {
            if (t.getUserId().equals(userId) && clientId.equals(t.getClientId())) {
                userTokens.add(t);
            }
        }
        return userTokens;
    }

    @Override
    public List<RevocableToken> getClientTokens(String clientId) {
        ArrayList<RevocableToken> clientTokens = new ArrayList<RevocableToken>();
        for (RevocableToken t : this._tokens.values()) {
            if (clientId.equals(t.getClientId())) {
                clientTokens.add(t);
            }
        }
        return clientTokens;
    }

    @Override
    public Log getLogger() {
        return this.logger;
    }

    public long getExpirationCheckInterval() {
        return expirationCheckInterval;
    }

    public void setExpirationCheckInterval(long expirationCheckInterval) {
        this.expirationCheckInterval = expirationCheckInterval;
    }

    private void checkExpired() {
        long now = System.currentTimeMillis();
        if ((now - lastExpiredCheck.getAndSet(now)) > getExpirationCheckInterval()) {

            ArrayList<RevocableToken> toRemove = new ArrayList<RevocableToken>();
            for (RevocableToken t : this._tokens.values()) {
                if (t.getExpiresAt() < now) {
                    toRemove.add(t);
                }
            }
            for (RevocableToken t : toRemove) {
                this._tokens.remove(t.getTokenId());
            }

            logger.debug("Removed " + toRemove.size() + " expired revocable tokens.");
        }

    }
}
