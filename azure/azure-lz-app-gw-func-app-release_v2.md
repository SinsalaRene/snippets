# Configuring Azure Function App API Exposure via Application Gateway

This guide provides detailed steps to configure an Azure Function App (Flexible Plan) in a spoke subscription to expose its API to the internet through an Application Gateway, routing traffic via a Fortinet HA Firewall in a hub VNet, while enforcing no direct internet traffic for the Function App. It includes expanded details on Application Gateway configuration and independent testing procedures for each component.

## Architecture Overview
- **Hub Subscription**: Contains a Fortinet HA Firewall in the hub VNet, managing all ingress/egress traffic.
- **Spoke Subscription**: Hosts the Function App (Flexible Plan) in a spoke VNet peered to the hub, with a private endpoint to secure inbound traffic.
- **Application Gateway Subscription**: Hosts an Application Gateway (with WAF) for public-facing API exposure.
- **Traffic Flow**: Internet → Application Gateway → Fortinet Firewall (hub) → Function App (spoke).

## Prerequisites
- Hub VNet with Fortinet HA Firewall deployed (e.g., internal IP `10.0.0.4`).
- Spoke VNet peered to the hub VNet with bidirectional peering.
- Function App deployed in the spoke subscription on a Flexible Plan, with a private endpoint in a subnet (e.g., `10.2.1.0/24`).
- Private DNS Zone (e.g., `privatelink.azurewebsites.net`) linked to the spoke and Application Gateway VNets.
- Application Gateway deployed in its subscription with a public IP and WAF enabled.
- User-defined route (UDR) table in the spoke VNet (if VNet integration is used) to route outbound traffic through the Fortinet Firewall.
- NSGs or Function App access restrictions to block direct internet access to the Function App.

## Configuration Steps

### Step 1: Configure Function App Private Endpoint
1. **Create Private Endpoint**:
   - In the Azure Portal, navigate to Function App → Settings → Networking → Private Endpoint Connections → Create.
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

### Step 2: Configure Fortinet HA Firewall
1. **Create Ingress Policy**:
   - In the Fortinet Firewall, create a policy to allow traffic from the Application Gateway’s subnet (e.g., `10.1.0.0/24`) to the Function App’s private endpoint subnet (e.g., `10.2.1.0/24`).
   - Example: Source IP: `10.1.0.0/24`, Destination IP: `10.2.1.5` (Function App private IP), Port: 443 (HTTPS).
2. **Create Egress Policy**:
   - Allow return traffic from the Function App’s subnet to the Application Gateway’s subnet.
   - Example: Source IP: `10.2.1.5`, Destination IP: `10.1.0.0/24`, Port: 443.
3. **NAT Configuration**:
   - If NAT is required, configure the firewall to translate traffic from the Application Gateway to the Function App’s private IP.
   - Example: Inbound NAT rule mapping Application Gateway traffic to `10.2.1.5:443`.
4. **Enable Logging**:
   - Enable logging for these policies to monitor traffic and troubleshoot issues.

### Step 3: Configure Application Gateway
1. **Create Backend Pool**:
   - In the Azure Portal, go to Application Gateway → Backend Pools → Add.
   - Name: `FunctionAppBackend`.
   - Add a target:
     - Use the Function App’s hostname (e.g., `myfunctionapp.azurewebsites.net`) or private IP (e.g., `10.2.1.5`).
     - If using hostname, ensure the Private DNS Zone resolves it to the private IP within the VNet.
2. **Configure HTTP Settings**:
   - Go to HTTP Settings → Add.
   - Name: `FunctionAppHttpSettings`.
   - Protocol: HTTPS (port 443).
   - Enable “Use for App Service” to simplify configuration for Azure App Services/Function Apps.
   - If using end-to-end SSL, upload the Function App’s certificate or use a trusted root certificate.
   - Set “Host name override” to `myfunctionapp.azurewebsites.net` if using hostname-based routing.
   - Enable “Create a new probe” or configure a custom probe (see below).
3. **Create Health Probe**:
   - Name: `FunctionAppHealthProbe`.
   - Protocol: HTTPS.
   - Host: `myfunctionapp.azurewebsites.net` (or private IP).
   - Path: `/api/health` (implement a health endpoint in your Function App returning HTTP 200, e.g., a simple GET endpoint).
   - Interval: 30 seconds, Timeout: 30 seconds, Unhealthy threshold: 3.
   - Ensure the probe matches the HTTP settings (e.g., same host and port).
4. **Configure Listener**:
   - Go to Listeners → Add.
   - Name: `FunctionAppListener`.
   - Frontend IP: Public IP of the Application Gateway.
   - Protocol: HTTPS (port 443).
   - Upload a valid SSL certificate (e.g., from a trusted CA or self-signed for testing).
   - Hostname: `api.contoso.com` (or your custom domain).
5. **Create Routing Rule**:
   - Go to Rules → Add (Basic Rule).
   - Name: `FunctionAppRule`.
   - Associate the listener (`FunctionAppListener`) with the backend pool (`FunctionAppBackend`) and HTTP settings (`FunctionAppHttpSettings`).
6. **WAF Configuration**:
   - If using WAF, go to Web Application Firewall → Settings.
   - Enable WAF in Prevention mode with OWASP 3.2 ruleset.
   - Customize rules to avoid false positives (e.g., exclude specific rules for your API’s patterns).
   - Enable logging for WAF to monitor blocked requests.
7. **UDR for Routing**:
   - In the Application Gateway’s subnet (e.g., `10.1.0.0/24`), apply a UDR to route traffic to the Function App’s subnet (e.g., `10.2.1.0/24`) via the Fortinet Firewall’s IP (e.g., `10.0.0.4`).
   - Example: Route table with destination `10.2.1.0/24`, next hop type `Virtual Appliance`, next hop IP `10.0.0.4`.

### Step 4: Verify and Test Configurations
Each component should be tested independently to ensure proper setup before end-to-end testing.

#### **Test 1: Function App Private Endpoint**
- **Goal**: Verify the Function App is accessible only via its private endpoint.
- **Steps**:
  1. Deploy a test VM in the spoke VNet (same VNet as the Function App’s private endpoint).
  2. From the VM, run: `curl -k https://myfunctionapp.azurewebsites.net/api/health`.
     - Expected: HTTP 200 response from the health endpoint.
     - If using a private IP: `curl -k https://10.2.1.5/api/health`.
  3. From an external machine (outside Azure), run: `curl https://myfunctionapp.azurewebsites.net/api/health`.
     - Expected: Connection timeout or failure (public access is blocked).
  4. Check the Private DNS Zone:
     - Run `nslookup myfunctionapp.azurewebsites.net` from the test VM.
     - Expected: Resolves to the private IP (e.g., `10.2.1.5`).
  5. Verify NSG/Access Restrictions:
     - Attempt `curl` from a different VNet (not peered).
     - Expected: Access denied unless explicitly allowed.
- **Troubleshooting**:
  - If resolution fails, ensure the Private DNS Zone is linked to the spoke VNet.
  - If access fails, check NSG rules or Function App access restrictions.

#### **Test 2: Fortinet Firewall Routing**
- **Goal**: Confirm the firewall correctly routes traffic between the Application Gateway and Function App.
- **Steps**:
  1. In the Fortinet Firewall, check policy logs for traffic from the Application Gateway’s subnet (e.g., `10.1.0.0/24`) to the Function App’s private IP (e.g., `10.2.1.5`).
     - Expected: Logs show allowed traffic on port 443.
  2. Temporarily disable the ingress policy and attempt a request from a test VM in the Application Gateway’s VNet to the Function App.
     - Expected: Request fails (connection timeout or blocked).
  3. Re-enable the policy and retry.
     - Expected: Request succeeds.
  4. Verify return traffic by checking logs for traffic from `10.2.1.5` to `10.1.0.0/24`.
- **Troubleshooting**:
  - If traffic is blocked, verify firewall policy source/destination IPs and ports.
  - Check NAT rules if translation is required.
  - Ensure VNet peering is correctly configured (gateway transit enabled if needed).

#### **Test 3: Application Gateway Configuration**
- **Goal**: Validate the Application Gateway’s backend, health probe, and routing.
- **Steps**:
  1. Check backend health:
     - Go to Application Gateway → Backend Health.
     - Expected: `FunctionAppBackend` shows “Healthy” for the Function App’s private IP or hostname.
  2. Test listener:
     - From an external machine, run: `curl https://api.contoso.com/api/health`.
     - Expected: HTTP 200 response from the Function App.
  3. Test WAF:
     - Send a malicious request (e.g., `curl https://api.contoso.com/api/health?test=<script>`).
     - Expected: WAF blocks the request (HTTP 403 or similar).
     - Check WAF logs for blocked request details.
  4. Verify UDR:
     - Temporarily remove the UDR from the Application Gateway’s subnet.
     - Attempt a request to `api.contoso.com`.
     - Expected: Request fails (traffic doesn’t reach the Function App).
     - Re-apply the UDR and retry (should succeed).
- **Troubleshooting**:
  - If backend is unhealthy, verify the health probe path and certificate settings.
  - If requests fail, check listener SSL certificate and routing rule configuration.
  - If WAF blocks legitimate requests, review and exclude specific rules.

#### **Test 4: End-to-End Connectivity**
- **Goal**: Confirm the full traffic flow (Internet → Application Gateway → Firewall → Function App).
- **Steps**:
  1. From an external machine, run: `curl https://api.contoso.com/api/health`.
     - Expected: HTTP 200 response.
  2. Check Application Gateway logs (Monitoring → Logs) for request details.
     - Query: `AzureDiagnostics | where ResourceType == "APPLICATIONGATEWAYS" and OperationName == "ApplicationGatewayAccess"`.
     - Expected: Logs show requests hitting the backend.
  3. Check Fortinet Firewall logs for traffic from Application Gateway to Function App and back.
     - Expected: Bidirectional traffic logged.
  4. Attempt direct access to the Function App: `curl https://myfunctionapp.azurewebsites.net/api/health`.
     - Expected: Connection timeout (public endpoint inaccessible).
- **Troubleshooting**:
  - If end-to-end fails, isolate the issue by re-running Tests 1–3.
  - Verify VNet peering and DNS resolution across subscriptions.

### Security Considerations
- **End-to-End SSL**: Ensure HTTPS is used from the client to the Application Gateway and from the Application Gateway to the Function App. Upload the Function App’s certificate to the HTTP settings if needed.
- **WAF Tuning**: Regularly review WAF logs and adjust rules to minimize false positives.
- **NSG Hardening**: Apply NSGs to the private endpoint subnet to allow only Application Gateway traffic.
- **Firewall Updates**: Keep Fortinet Firewall firmware and policies updated to address vulnerabilities.
- **Monitoring**: Enable Application Insights for the Function App and Azure Monitor for the Application Gateway to track performance and errors.

### Diagram
```mermaid
graph TD
    A[Internet] -->|HTTPS| B[Application Gateway <br> (Public IP, WAF, 10.1.0.0/24)]
    B -->|Private IP, via UDR| C[Fortinet HA Firewall <br> (Hub VNet, 10.0.0.4)]
    C -->|Private IP| D[Function App <br> (Spoke VNet, Private Endpoint, 10.2.1.5)]
    D -->|Return Traffic| C
    C -->|Return Traffic| B
    B -->|HTTPS| A
```