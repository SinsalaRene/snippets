# Configuring Azure Function App API Exposure via Application Gateway (Non-SSL)

This guide details how to configure an Azure Function App (Flexible Plan) in a spoke subscription to expose its API to the internet via an Application Gateway using HTTP (no SSL/certificates) for testing purposes, routing traffic through a Fortinet HA Firewall in a hub VNet, while enforcing no direct internet traffic for the Function App. It includes detailed Application Gateway configuration and independent testing procedures.

## Architecture Overview
- **Hub Subscription**: Fortinet HA Firewall in the hub VNet (e.g., internal IP `10.0.0.4`).
- **Spoke Subscription**: Function App (Flexible Plan) in a spoke VNet peered to the hub, with a private endpoint for inbound traffic.
- **Application Gateway Subscription**: Application Gateway (with optional WAF) for public-facing API exposure.
- **Traffic Flow**: Internet → Application Gateway (HTTP) → Fortinet Firewall (hub) → Function App (spoke, private endpoint).

## Prerequisites
- Hub VNet with Fortinet HA Firewall deployed.
- Spoke VNet peered to the hub VNet with bidirectional peering.
- Function App deployed in the spoke subscription on a Flexible Plan, with a private endpoint in a subnet (e.g., `10.2.1.0/24`).
- Private DNS Zone (e.g., `privatelink.azurewebsites.net`) linked to the spoke and Application Gateway VNets.
- Application Gateway deployed with a public IP (WAF optional for non-SSL).
- NSGs or Function App access restrictions to block direct internet access to the Function App.
- No VNet integration required, as the Function App has no outbound network needs.

## Warnings
- **Security Risk**: Using HTTP without SSL exposes traffic to interception and tampering. This setup is for **testing only** and should not be used in production.
- **Azure Limitations**: Some Function App features (e.g., private endpoint management) may still require HTTPS for Azure platform interactions, but API traffic can use HTTP.
- **WAF Considerations**: WAF functionality is less effective without HTTPS, as traffic is not encrypted.

## Configuration Steps

### Step 1: Configure Function App Private Endpoint
1. **Create Private Endpoint**:
   - In the Azure Portal, go to Function App → Settings → Networking → Private Endpoint Connections → Create.
   - Select the spoke VNet and a subnet (e.g., `PrivateEndpointSubnet`, `10.2.1.0/24`, minimum /28).
   - Choose the Function App as the target resource (sub-resource: `sites`).
   - Enable integration with a Private DNS Zone (e.g., `privatelink.azurewebsites.net`).
2. **Configure Private DNS Zone**:
   - In the Private DNS Zone, ensure an A record maps the Function App’s hostname (e.g., `myfunctionapp.azurewebsites.net`) to the private IP (e.g., `10.2.1.5`).
   - Link the Private DNS Zone to the spoke VNet and the Application Gateway’s VNet (via peering).
3. **Restrict Public Access**:
   - Go to Function App → Settings → Networking → Access Restrictions.
   - Add a rule to allow traffic only from the Application Gateway’s subnet (e.g., `10.1.0.0/24`).
   - Deny all other inbound traffic (e.g., `0.0.0.0/0`).
4. **Enable HTTP**:
   - Ensure the Function App supports HTTP traffic (default behavior).
   - Implement a health endpoint (e.g., `/api/health`) returning HTTP 200 for testing.

### Step 2: Configure Fortinet HA Firewall
1. **Create Ingress Policy**:
   - In the Fortinet Firewall, create a policy to allow HTTP traffic from the Application Gateway’s subnet (e.g., `10.1.0.0/24`) to the Function App’s private endpoint subnet (e.g., `10.2.1.0/24`).
   - Example: Source IP: `10.1.0.0/24`, Destination IP: `10.2.1.5`, Port: 80 (HTTP).
2. **Create Egress Policy**:
   - Allow return traffic from the Function App’s subnet to the Application Gateway’s subnet.
   - Example: Source IP: `10.2.1.5`, Destination IP: `10.1.0.0/24`, Port: 80.
3. **NAT Configuration** (if needed):
   - Configure NAT to forward Application Gateway traffic to the Function App’s private IP on port 80.
   - Example: Inbound NAT rule mapping `10.1.0.0/24:80` to `10.2.1.5:80`.
4. **Enable Logging**:
   - Enable logging for these policies to monitor HTTP traffic and troubleshoot.

### Step 3: Configure Application Gateway (Non-SSL)
1. **Create Backend Pool**:
   - In the Azure Portal, go to Application Gateway → Backend Pools → Add.
   - Name: `FunctionAppBackend`.
   - Add a target:
     - Use the Function App’s hostname (e.g., `myfunctionapp.azurewebsites.net`) or private IP (e.g., `10.2.1.5`).
     - If using hostname, ensure the Private DNS Zone resolves it to the private IP.
2. **Configure HTTP Settings**:
   - Go to HTTP Settings → Add.
   - Name: `FunctionAppHttpSettings`.
   - Protocol: HTTP (port 80).
   - Enable “Use for App Service” to simplify configuration.
   - Set “Host name override” to `myfunctionapp.azurewebsites.net` if using hostname-based routing.
   - Disable “Use well-known CA certificate” (not applicable for HTTP).
   - Enable “Create a new probe” or configure a custom probe (see below).
3. **Create Health Probe**:
   - Name: `FunctionAppHealthProbe`.
   - Protocol: HTTP.
   - Host: `myfunctionapp.azurewebsites.net` (or private IP, e.g., `10.2.1.5`).
   - Path: `/api/health` (ensure the Function App has a health endpoint returning HTTP 200).
   - Interval: 30 seconds, Timeout: 30 seconds, Unhealthy threshold: 3.
   - Ensure the probe matches the HTTP settings (port 80, no SSL).
4. **Configure Listener**:
   - Go to Listeners → Add.
   - Name: `FunctionAppListener`.
   - Frontend IP: Public IP of the Application Gateway.
   - Protocol: HTTP (port 80).
   - Hostname: `api.contoso.com` (or leave blank for IP-based access).
   - **Note**: No SSL certificate is required for HTTP.
5. **Create Routing Rule**:
   - Go to Rules → Add (Basic Rule).
   - Name: `FunctionAppRule`.
   - Associate the listener (`FunctionAppListener`) with the backend pool (`FunctionAppBackend`) and HTTP settings (`FunctionAppHttpSettings`).
6. **WAF Configuration** (if enabled):
   - Go to Web Application Firewall → Settings.
   - Enable WAF in Prevention mode with OWASP 3.2 ruleset.
   - Customize rules to avoid false positives for your API’s patterns.
   - **Note**: WAF effectiveness is reduced without SSL, as traffic is not encrypted.
7. **UDR for Routing**:
   - In the Application Gateway’s subnet (e.g., `10.1.0.0/24`), apply a UDR to route traffic to the Function App’s subnet (e.g., `10.2.1.0/24`) via the Fortinet Firewall’s IP (e.g., `10.0.0.4`).
   - Example: Route table with destination `10.2.1.0/24`, next hop type `Virtual Appliance`, next hop IP `10.0.0.4`.

### Step 4: Verify and Test Configurations
Each component is tested independently to ensure proper setup before end-to-end testing, using HTTP.

#### **Test 1: Function App Private Endpoint**
- **Goal**: Verify the Function App is accessible only via its private endpoint over HTTP.
- **Steps**:
  1. Deploy a test VM in the spoke VNet (same VNet as the Function App’s private endpoint).
  2. From the VM, run: `curl http://myfunctionapp.azurewebsites.net/api/health`.
     - Expected: HTTP 200 response from the health endpoint.
     - If using private IP: `curl http://10.2.1.5/api/health`.
  3. From an external machine (outside Azure), run: `curl http://myfunctionapp.azurewebsites.net/api/health`.
     - Expected: Connection timeout or failure (public access blocked by private endpoint).
  4. Check Private DNS Zone:
     - Run `nslookup myfunctionapp.azurewebsites.net` from the test VM.
     - Expected: Resolves to the private IP (e.g., `10.2.1.5`).
  5. Verify NSG/Access Restrictions:
     - Attempt `curl http://myfunctionapp.azurewebsites.net/api/health` from a different VNet (not peered).
     - Expected: Access denied unless explicitly allowed.
- **Troubleshooting**:
  - If resolution fails, verify the Private DNS Zone is linked to the spoke VNet.
  - If access fails, check NSG rules or Function App access restrictions for port 80.
  - Ensure the Function App allows HTTP traffic (default behavior).

#### **Test 2: Fortinet Firewall Routing**
- **Goal**: Confirm the firewall routes HTTP traffic between the Application Gateway and Function App.
- **Steps**:
  1. In the Fortinet Firewall, check policy logs for HTTP traffic from the Application Gateway’s subnet (e.g., `10.1.0.0/24`) to the Function App’s private IP (e.g., `10.2.1.5`) on port 80.
     - Expected: Logs show allowed traffic.
  2. Temporarily disable the ingress policy and attempt a request from a test VM in the Application Gateway’s VNet to the Function App (`curl http://10.2.1.5/api/health`).
     - Expected: Request fails (connection timeout or blocked).
  3. Re-enable the policy and retry.
     - Expected: Request succeeds with HTTP 200.
  4. Verify return traffic logs for traffic from `10.2.1.5` to `10.1.0.0/24` on port 80.
- **Troubleshooting**:
  - If traffic is blocked, verify firewall policy source/destination IPs and port 80.
  - Check NAT rules if translation is applied.
  - Ensure VNet peering allows traffic forwarding (gateway transit if needed).

#### **Test 3: Application Gateway Configuration**
- **Goal**: Validate the Application Gateway’s backend, health probe, and routing over HTTP.
- **Steps**:
  1. Check backend health:
     - Go to Application Gateway → Backend Health.
     - Expected: `FunctionAppBackend` shows “Healthy” for the Function App’s private IP or hostname.
  2. Test listener:
     - From an external machine, run: `curl http://api.contoso.com/api/health` (or use the Application Gateway’s public IP, e.g., `curl http://<public-ip>/api/health`).
     - Expected: HTTP 200 response from the Function App.
  3. Test WAF (if enabled):
     - Send a malicious request (e.g., `curl http://api.contoso.com/api/health?test=<script>`).
     - Expected: WAF blocks the request (HTTP 403 or similar).
     - Check WAF logs for blocked request details.
  4. Verify UDR:
     - Temporarily remove the UDR from the Application Gateway’s subnet.
     - Attempt a request to `http://api.contoso.com/api/health`.
     - Expected: Request fails (traffic doesn’t reach the Function App).
     - Re-apply the UDR and retry (should succeed).
- **Troubleshooting**:
  - If backend is unhealthy, verify the health probe path and ensure port 80 is open.
  - If requests fail, check listener configuration (port 80, no SSL).
  - If WAF blocks legitimate requests, review and exclude specific rules.

#### **Test 4: End-to-End Connectivity**
- **Goal**: Confirm the full traffic flow (Internet → Application Gateway → Firewall → Function App) over HTTP.
- **Steps**:
  1. From an external machine, run: `curl http://api.contoso.com/api/health`.
     - Expected: HTTP 200 response.
  2. Check Application Gateway logs (Monitoring → Logs):
     - Query: `AzureDiagnostics | where ResourceType == "APPLICATIONGATEWAYS" and OperationName == "ApplicationGatewayAccess"`.
     - Expected: Logs show HTTP requests hitting the backend.
  3. Check Fortinet Firewall logs for traffic from Application Gateway to Function App and back on port 80.
     - Expected: Bidirectional traffic logged.
  4. Attempt direct access to the Function App: `curl http://myfunctionapp.azurewebsites.net/api/health`.
     - Expected: Connection timeout (public endpoint inaccessible due to private endpoint).
- **Troubleshooting**:
  - If end-to-end fails, isolate the issue by re-running Tests 1–3.
  - Verify VNet peering and DNS resolution across subscriptions.

### Security Considerations
- **HTTP Risks**: Without SSL, traffic is unencrypted and vulnerable. Transition to HTTPS with certificates for production.
- **Access Control**: Use NSGs and Function App access restrictions to limit traffic to the Application Gateway’s subnet.
- **WAF Tuning**: Adjust WAF rules to minimize false positives, but note reduced effectiveness without encryption.
- **Monitoring**: Enable Application Insights for the Function App and Azure Monitor for the Application Gateway to track performance and errors.
- **Firewall Hardening**: Regularly update Fortinet Firewall policies and firmware.

### Transitioning to SSL
To add SSL later:
1. Update the Application Gateway listener to use HTTPS (port 443) with a valid SSL certificate.
2. Update HTTP settings and health probe to use HTTPS (port 443).
3. Configure the Fortinet Firewall to allow traffic on port 443.
4. Ensure the Function App supports HTTPS (default) and upload a certificate if required for end-to-end SSL.

### Diagram
```mermaid
graph TD
    A[Internet] -->|HTTP| B[Application Gateway <br> (Public IP, WAF, 10.1.0.0/24)]
    B -->|Private IP, via UDR| C[Fortinet HA Firewall <br> (Hub VNet, 10.0.0.4)]
    C -->|Private IP| D[Function App <br> (Spoke VNet, Private Endpoint, 10.2.1.5)]
    D -->|Return Traffic| C
    C -->|Return Traffic| B
    B -->|HTTP| A
```