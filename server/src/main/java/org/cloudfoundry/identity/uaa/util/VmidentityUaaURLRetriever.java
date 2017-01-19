package org.cloudfoundry.identity.uaa.util;

import java.net.InetAddress;
import java.net.URL;

import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityUaaURLRetriever {

    private static final int DEFAULT_HTTPS_PORT = 443;

    private CasIdmClient idmClient;

    public VmidentityUaaURLRetriever(CasIdmClient idmClient) {
        this.idmClient = idmClient;
    }

    public String getEntityBaseFQDN() throws Exception {
        return buildEndpoint(false);
    }

    public String getEntityBaseIP() throws Exception {
        return buildEndpoint(true);
    }

    private String buildEndpoint(boolean useIP) throws Exception {
        String systemTenant = idmClient.getSystemTenant();
        String serviceUri = idmClient.getEntityID(systemTenant);

        StringBuilder builder = new StringBuilder();

        // Need to strip off any websso path that lingers and add the uaa path instead
        URL url = new URL(serviceUri);
        builder.append(url.getProtocol() + "://");
        if (useIP) {
            InetAddress address = InetAddress.getByName(url.getHost());
            builder.append(address.getHostAddress());
        } else {
            builder.append(url.getHost());
        }
        if (url.getPort() != -1 && url.getPort() != DEFAULT_HTTPS_PORT) {
            builder.append(":" + url.getPort());
        }
        builder.append("/uaa");

        return builder.toString();
    }

}
