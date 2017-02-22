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
package org.cloudfoundry.identity.uaa.client;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;
import org.springframework.util.Assert;

import com.vmware.identity.idm.OIDCClient;
import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityClientMetadataProvisioning implements ClientMetadataProvisioning {

    private static final Log logger = LogFactory.getLog(VmidentityClientMetadataProvisioning.class);

    private CasIdmClient idmClient;

    VmidentityClientMetadataProvisioning(CasIdmClient idmClient) {
        Assert.notNull(idmClient);
        this.idmClient = idmClient;
    }

    @Override
    public List<ClientMetadata> retrieveAll() {
        logger.debug("Retrieving UI details for all clients");

        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            Collection<OIDCClient> clients = idmClient.getOIDCClients(tenant);
            List<ClientMetadata> clientMetadata = new ArrayList<ClientMetadata>(clients.size());
            for (OIDCClient client : clients) {
                clientMetadata.add(mapOIDCClient(client, tenant));
            }
            return clientMetadata;
        } catch (Exception e) {
            logger.error("Unable to retrieve UI details for all clients", e);
            throw new VmidentityDataAccessException("Unable to retrieve UI details for all clients");
        }
    }

    @Override
    public ClientMetadata retrieve(String clientId) {
        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            OIDCClient client = idmClient.getOIDCClient(tenant, clientId);
            return mapOIDCClient(client, tenant);
        } catch (Exception e) {
            logger.error("Unable to retrieve UI details for client: " + clientId, e);
            throw new VmidentityDataAccessException("Unable to retrieve UI details for client: " + clientId);
        }
    }

    @Override
    public ClientMetadata update(ClientMetadata resource) {
        logger.debug("Updating metadata for client: " + resource.getClientId());

        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            OIDCClient client = idmClient.getOIDCClient(tenant, resource.getClientId());

            OIDCClient.Builder builder = new OIDCClient.Builder(client.getClientId())
                    .authnRequestClientAssertionLifetimeMS(client.getAuthnRequestClientAssertionLifetimeMS())
                    .certSubjectDN(client.getCertSubjectDN())
                    .idTokenSignedResponseAlg(client.getIdTokenSignedResponseAlg())
                    .logoutUri(client.getLogoutUri())
                    .postLogoutRedirectUris(client.getPostLogoutRedirectUris())
                    .redirectUris(client.getRedirectUris())
                    .tokenEndpointAuthMethod(client.getTokenEndpointAuthMethod())
                    .tokenEndpointAuthSigningAlg(client.getTokenEndpointAuthSigningAlg())
                    .authorities(client.getAuthorities())
                    .clientSecret(client.getClientSecret());

            // TODO:
            // resource.isShowOnHomePage();
            // resource.getAppLaunchUrl();
            // resource.getAppIcon();
            // resource.getClientName();

            idmClient.setOIDCClient(tenant, builder.build());
        } catch (Exception e) {
            logger.error("Unable to update metadata for client: " + resource.getClientId(), e);
            throw new VmidentityDataAccessException("Unable to update metadata for client: " + resource.getClientId());
        }

        return retrieve(resource.getClientId());
    }

    public static ClientMetadata mapOIDCClient(OIDCClient client, String tenant) {
        ClientMetadata clientMetadata = new ClientMetadata();
        clientMetadata.setClientId(client.getClientId());
        clientMetadata.setIdentityZoneId(tenant); // TODO check if this should be tenant or the zone (only matters for default)
        clientMetadata.setShowOnHomePage(false); // TODO Get an actual value
        clientMetadata.setAppLaunchUrl(null); // TODO Get an actual value
        clientMetadata.setAppIcon(null); // TODO Get an actual value
        clientMetadata.setClientName(null); // TODO Get an actual value
        return clientMetadata;
    }

}
