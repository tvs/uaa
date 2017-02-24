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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;
import org.springframework.util.Assert;

import com.vmware.identity.idm.OIDCClient;
import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityClientMetadataProvisioning implements ClientMetadataProvisioning {

    private static final Log logger = LogFactory.getLog(VmidentityClientMetadataProvisioning.class);

    private static final String CLIENT_METADATA_SHOW_ON_HOME_PAGE = "show_on_home_page";
    private static final String CLIENT_METADATA_APP_LAUNCH_URL = "app_launch_url";
    private static final String CLIENT_METADATA_APP_ICON = "app_icon";

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

            OIDCClient.Builder builder = new OIDCClient.Builder(client);

            Map<String, Object> additionalInformation = client.getAdditionalInformation();
            if (additionalInformation == null) {
                additionalInformation = new HashMap<String, Object>();
            }
            if (resource.getClientName() != null) {
                additionalInformation.put(ClientConstants.CLIENT_NAME, resource.getClientName());
            }

            if (resource.isShowOnHomePage()) {
                additionalInformation.put(CLIENT_METADATA_SHOW_ON_HOME_PAGE, resource.isShowOnHomePage());
            }

            if (resource.getAppLaunchUrl() != null) {
                additionalInformation.put(CLIENT_METADATA_APP_LAUNCH_URL, resource.getAppLaunchUrl());
            }

            if (resource.getAppIcon() != null) {
                additionalInformation.put(CLIENT_METADATA_APP_ICON, resource.getAppIcon());
            }

            if (!additionalInformation.isEmpty()) {
                builder.additionalInformation(additionalInformation);
            }

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

        Map<String, Object> additionalInformation = client.getAdditionalInformation();
        if (additionalInformation != null) {
            Object showOnHomepageFromAddInfo = additionalInformation.get(CLIENT_METADATA_SHOW_ON_HOME_PAGE);
            if ((showOnHomepageFromAddInfo instanceof Boolean && (Boolean) showOnHomepageFromAddInfo || "true".equals(showOnHomepageFromAddInfo))) {
                clientMetadata.setShowOnHomePage(true);
            }

            try {
                clientMetadata.setAppLaunchUrl(new URL((String) additionalInformation.get(CLIENT_METADATA_APP_LAUNCH_URL)));
            } catch (MalformedURLException e) {
                // it is safe to ignore this as client_metadata content is always created from a ClientMetadata instance whose launch url property is strongly typed to URL
            }

            clientMetadata.setAppIcon((String) additionalInformation.get(CLIENT_METADATA_APP_ICON));
            clientMetadata.setClientName((String) additionalInformation.get(ClientConstants.CLIENT_NAME));
        }
        return clientMetadata;
    }

}
