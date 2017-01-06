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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.VmidentityIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;

import com.vmware.identity.idm.Tenant;
import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityIdentityZoneProvisioning implements IdentityZoneProvisioning {

    private final Log logger = LogFactory.getLog(VmidentityIdentityProviderProvisioning.class);

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
            String systemTenant = this._idmClient.getSystemTenant();
            String tenant = VmidentityUtils.getTenantName(id, this._idmClient.getSystemTenant());
            Tenant t = this._idmClient.getTenant(tenant);

            return identityZoneForTenant(t, systemTenant.equalsIgnoreCase(tenant));
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
            String systemTenant = this._idmClient.getSystemTenant();
            ArrayList<IdentityZone> list = new ArrayList<IdentityZone>();
            for (String tenant : this._idmClient.getAllTenants()) {
                list.add(identityZoneForTenant(this._idmClient.getTenant(tenant),
                        systemTenant.equalsIgnoreCase(tenant)));
            }

            return list;
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to retrieve zones.", ex);
        }
    }

    private IdentityZone identityZoneForTenant(Tenant t, boolean systemTenant) {
        IdentityZone identityZone = null;
        if (systemTenant) {
            identityZone = IdentityZone.getUaa();
        } else {
            identityZone = new IdentityZone();

            identityZone.setId(t.getName());
            identityZone.setVersion(1);
            // identityZone.setCreated(rs.getTimestamp(3));
            // identityZone.setLastModified(rs.getTimestamp(4));
            identityZone.setName(t.getName());
            identityZone.setSubdomain(t.getName());
            identityZone.setDescription(t._longName);
        }

        // todo: default for now, should implement
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        if (this._configs.containsKey(t.getName())) {
            config = this._configs.get(t.getName());
        }
        identityZone.setConfig(config);

        return identityZone;
    }
}
