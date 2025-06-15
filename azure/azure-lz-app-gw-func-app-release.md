# Configuring Azure Function App API Exposure via Application Gateway (AI Generated, not fact checked)

This guide outlines how to configure an Azure Function App (Flexible Plan) in a spoke subscription to expose its API to the internet through an Application Gateway, routing traffic via a Fortinet HA Firewall in a hub VNet, while enforcing no direct internet traffic for the Function App.

## Architecture Overview
- **Hub Subscription**: Contains a Fortinet HA Firewall in the hub VNet, managing all ingress/egress traffic.
- **Spoke Subscription**: Hosts the Function App (Flexible Plan) in a spoke VNet peered to the hub. The Function App is VNet-integrated and restricted from direct internet access.
- **Application Gateway Subscription**: Hosts an Application Gateway (with WAF) for public-facing API exposure.
- **Traffic Flow**: Internet → Application Gateway → Fortinet Firewall (hub) → Function App (spoke).

## Prerequisites
- Hub VNet with Fortinet HA Firewall deployed and configured for traffic routing.
- Spoke VNet peered to the hub VNet with bidirectional peering.
- Application Gateway deployed in its subscription, with a public IP and WAF enabled.
- Spoke subscription has a user-defined route (UDR) table enforcing outbound traffic to route through the Fortinet Firewall.
- Azure Private DNS Zones for resolving private endpoints or VNet-integrated services.
- Function App created in the spoke subscription on a Flexible Plan (Premium or Elastic Premium).

## Configuration Steps

### Step 1: Configure Function App VNet Integration
1. **Enable VNet Integration**:
   - In the Azure Portal, navigate to the Function App → Settings → Networking → VNet Integration.
   - Select the spoke VNet and a dedicated subnet (e.g., `FunctionAppSubnet`, minimum /28).
   - Ensure the subnet has a UDR associated to route `0.0.0.0/0` traffic to the Fortinet Firewall’s internal IP (e.g., `10.0.0.4`).
2. **Restrict Public Access**:
   - Go to Function App → Settings → Networking → Access Restrictions.
   - Deny all inbound traffic from `0.0.0.0/0` except for Azure services (if needed for management).
   - Optionally, use private endpoints for Function App management (if supported in Flexible Plan).
3. **Set DNS Resolution**:
   - Ensure the Function App resolves to a private IP within the VNet by linking the spoke VNet to an Azure Private DNS Zone (e.g., `privatelink.azurewebsites.net`).
   - Configure the Fortinet Firewall to forward DNS requests to Azure DNS (`168.63.129.16`) or a custom DNS server.

### Step 2: Configure Fortinet HA Firewall
1. **Create Routing Rules**:
   - In the Fortinet Firewall, configure a policy to allow traffic from the Application Gateway’s subnet (e.g., `10.1.0.0/24`) to the Function App’s subnet (e.g., `10.2.1.0/24`).
   - Set up NAT rules to forward traffic from the Application Gateway to the Function App’s private IP.
2. **Inspect Traffic**:
   - Enable SSL inspection (if required) for traffic between the Application Gateway and Function App.
   - Ensure the firewall logs and monitors API traffic for security.
3. **Return Traffic**:
   - Configure a policy to allow return traffic from the Function App to the Application Gateway.
   - Ensure UDRs in the spoke VNet route outbound Function App traffic through the firewall.

### Step 3: Configure Application Gateway
1. **Create Backend Pool**:
   - In the Application Gateway, create a backend pool targeting the Function App’s private IP or hostname (e.g., `myfunctionapp.azurewebsites.net`).
   - If using hostname, ensure DNS resolves to the private IP via the Private DNS Zone.
2. **Configure HTTP Settings**:
   - Create HTTP settings for port 443 (HTTPS) or 80 (HTTP, for testing).
   - Enable “Use for App Service” if directly targeting the Function App hostname.
   - Upload a trusted certificate if using end-to-end SSL.
3. **Set Up Listener and Rule**:
   - Create a listener on the public IP for port 443 (HTTPS) with a valid SSL certificate.
   - Create a routing rule mapping the listener to the backend pool via the HTTP settings.
4. **Health Probe**:
   - Configure a health probe to check the Function App’s health (e.g., `/api/health` if implemented).
   - Ensure the probe uses the private IP or hostname and matches the HTTP settings.
5. **WAF Configuration**:
   - Enable WAF rules to protect against common API vulnerabilities (e.g., SQL injection, XSS).
   - Customize rules if the Function App API has specific requirements.

### Step 4: Route Traffic from Application Gateway to Hub
1. **VNet Peering**:
   - Ensure the Application Gateway’s VNet is peered with the hub VNet (bidirectional).
   - Confirm that the peering allows traffic forwarding and gateway transit if needed.
2. **UDR for Application Gateway**:
   - In the Application Gateway’s subnet, apply a UDR to route traffic to the Function App’s subnet (e.g., `10.2.1.0/24`) via the Fortinet Firewall’s IP (e.g., `10.0.0.4`).
3. **Firewall Policy**:
   - Update the Fortinet Firewall to allow traffic from the Application Gateway’s subnet to the Function App’s subnet, with appropriate NAT if needed.

### Step 5: Test and Validate
1. **Test API Access**:
   - Access the API via the Application Gateway’s public IP or DNS (e.g., `https://api.contoso.com`).
   - Verify the request reaches the Function App and returns the expected response.
2. **Check Firewall Logs**:
   - Confirm in the Fortinet Firewall logs that traffic flows correctly (Application Gateway → Function App → Return).
3. **Monitor Security**:
   - Review WAF logs in the Application Gateway for blocked threats.
   - Ensure no direct internet access to the Function App is possible (e.g., via `curl` to its hostname).
4. **Validate DNS**:
   - Confirm that `nslookup myfunctionapp.azurewebsites.net` from within the VNet resolves to a private IP.

## Security Considerations
- **End-to-End Encryption**: Use HTTPS between the client, Application Gateway, and Function App. Configure the Fortinet Firewall to inspect SSL traffic if required.
- **Access Control**: Restrict Function App access to only the Application Gateway’s subnet via network security groups (NSGs) or Function App access restrictions.
- **Monitoring**: Enable Azure Monitor and Application Insights for the Function App to track performance and errors.
- **WAF Tuning**: Adjust WAF rules to minimize false positives for your API’s specific patterns.
- **Firewall Hardening**: Regularly update Fortinet Firewall policies and firmware to address vulnerabilities.

## Troubleshooting Tips
- **API Not Reachable**:
  - Check NSG rules on the Function App subnet.
  - Verify UDRs are correctly routing traffic through the firewall.
  - Ensure Private DNS Zone resolves the Function App hostname to a private IP.
- **WAF Blocking Requests**:
  - Review WAF logs and exclude specific rules if needed.
- **Firewall Dropping Traffic**:
  - Check Fortinet logs for denied packets and update policies.
- **Health Probe Failing**:
  - Ensure the Function App’s health endpoint is accessible and returns a 200 status.

## Diagram
```mermaid
graph TD
    A[Internet] -->|HTTPS| B[Application Gateway <br> (Public IP, WAF)]
    B -->|Private IP| C[Fortinet HA Firewall <br> (Hub VNet)]
    C -->|Private IP| D[Function App <br> (Spoke VNet, VNet Integration)]
    D -->|Return Traffic| C
    C -->|Return Traffic| B
    B -->|HTTPS| A
```