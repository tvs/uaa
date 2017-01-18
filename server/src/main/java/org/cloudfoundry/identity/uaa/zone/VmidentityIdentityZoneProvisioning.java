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
package org.cloudfoundry.identity.uaa.zone;

import java.io.StringWriter;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.openssl.PEMWriter;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;

import com.google.common.primitives.Ints;
import com.vmware.identity.idm.NoSuchTenantException;
import com.vmware.identity.idm.Tenant;
import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityIdentityZoneProvisioning implements IdentityZoneProvisioning {

    private final CasIdmClient _idmClient;
    private final ConcurrentHashMap<String, IdentityZoneConfiguration> _configs;

    public VmidentityIdentityZoneProvisioning(CasIdmClient idmClient) {
        this._idmClient = idmClient;
        this._configs = new ConcurrentHashMap<String, IdentityZoneConfiguration>();
    }

    @Override
    public IdentityZone create(IdentityZone identityZone) {
        throw new IllegalStateException("creating a tenant is not yet supported.");
    }

    @Override
    public IdentityZone update(IdentityZone identityZone) {
        try {
            // todo: no op - implement
            String systemTenant = this._idmClient.getSystemTenant();
            String tenant = VmidentityUtils.getTenantName(identityZone.getId(), systemTenant);
            this._configs.put(tenant, identityZone.getConfig());
            return this.retrieve(identityZone.getId());
        } catch (Exception ex) {
            throw new IllegalStateException(String.format("Failed to update provider Id '%s'.", identityZone.getId()), ex);
        }
    }

    @Override
    public IdentityZone retrieve(String id) {
        try {
            return getIdentityZoneFromId(id);
        } catch (NoSuchTenantException ex) {
            throw new ZoneDoesNotExistsException("Zone["+id+"] not found.", ex);
        } catch (Exception ex) {
            throw new IllegalStateException(String.format("Failed to retrieve provider Id '%s'.", id), ex);
        }
    }

    @Override
    public IdentityZone retrieveBySubdomain(String subdomain) {
        if (subdomain.isEmpty()) {
            subdomain = OriginKeys.UAA;
        }
        return this.retrieve(subdomain);
    }

    @Override
    public List<IdentityZone> retrieveAll() {
        try {
            ArrayList<IdentityZone> list = new ArrayList<IdentityZone>();
            for (String tenant : this._idmClient.getAllTenants()) {
                list.add(getIdentityZoneFromTenant(tenant));
            }
            
            return list;
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to retrieve zones.", ex);
        }
    }
    
    private IdentityZone identityZoneForTenant(String tenantName) throws Exception {
        IdentityZone zone = new IdentityZone();
        Tenant t = this._idmClient.getTenant(tenantName);
        
        zone.setId(t.getName());
        zone.setName(t.getName());
        zone.setSubdomain(t.getName());
        zone.setDescription(t._longName);
        zone.setVersion(1);
        
        return zone;
    }
    
    private void configureIdentityZone(String tenantName, IdentityZone zone) throws Exception {
        IdentityZoneConfiguration config = this._configs.get(tenantName);
        if (config == null) {
            config = new IdentityZoneConfiguration();
            this._configs.put(tenantName, config);
        }
        
        Map<String, String> keys = new HashMap<String, String>();
        PrivateKey privateKey = _idmClient.getTenantPrivateKey(tenantName);
        StringWriter writer = new StringWriter();
        
        try (PEMWriter pemWriter = new PEMWriter(writer)) {
            pemWriter.writeObject(privateKey);
        }
        
        keys.put("key-id-1", writer.toString());
        config.getTokenPolicy().setKeys(keys);
        config.getTokenPolicy().setActiveKeyId("key-id-1");
        config.getTokenPolicy().setAccessTokenValidity(
                Ints.saturatedCast(_idmClient.getMaximumBearerTokenLifetime(tenantName)));
        config.getTokenPolicy().setRefreshTokenValidity(
                Ints.saturatedCast(_idmClient.getMaximumBearerRefreshTokenLifetime(tenantName)));
        
        config.getSamlConfig().setPrivateKey(writer.toString());
        
        // IDM doesn't store a private key password - we should be able to get away without it, though
        // config.getSamlConfig().setPrivateKeyPassword(privateKeyPassword);
        
        KeyInfo keyInfo = new KeyInfo();
        keyInfo.setKeyId("key-id-1");
        keyInfo.setSigningKey(writer.toString());
        config.getSamlConfig().setCertificate(keyInfo.getVerifierKey());
        
        zone.setConfig(config);
    }

    private IdentityZone getIdentityZoneFromId(String id) throws Exception {
        String tenantName = id;
        IdentityZone zone = null;
        
        if (id.equalsIgnoreCase(IdentityZone.getUaa().getId())) {
            tenantName = this._idmClient.getSystemTenant();
            zone = IdentityZone.getUaa();
        } else {
            zone = identityZoneForTenant(tenantName);
        }
        
        configureIdentityZone(tenantName, zone);
        
        return zone;
    }
    
    private IdentityZone getIdentityZoneFromTenant(String tenantName) throws Exception {
        IdentityZone zone = null;
        String systemTenant = this._idmClient.getSystemTenant();
        
        if (tenantName.equalsIgnoreCase(systemTenant)) {
            zone = IdentityZone.getUaa();
        } else {
            zone = identityZoneForTenant(tenantName);
        }
        
        configureIdentityZone(tenantName, zone);
        
        return zone;
    }

}
