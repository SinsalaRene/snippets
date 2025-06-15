To provide a comprehensive explanation of the Azure Application Gateway components and their configurations in the context of your Azure Landing Zone setup, I’ll dive into each component, its purpose, how it’s configured for your scenario (exposing a Function App’s API over HTTP via a private endpoint, routed through a Fortinet HA Firewall), and why these configurations work. Since you’ve requested a non-SSL setup for testing (using HTTP), I’ll focus on that while explaining the mechanics and rationale behind each setting. This builds on the previous artifact (ID `111c0078-2204-4a47-b48f-bd92036d3bd6`) by providing deeper insights into the Application Gateway’s components and their interactions.

### Context Recap
- **Architecture**: You have a hub-and-spoke Azure Landing Zone with a Fortinet HA Firewall in the hub VNet, a Function App (Flexible Plan) in a spoke VNet with a private endpoint (no outbound network needs), and an Application Gateway in a separate subscription to expose the Function App’s API to the internet over HTTP (port 80) for testing.
- **Goal**: Expose the Function App’s API (e.g., `http://api.contoso.com/api/health`) via the Application Gateway, routing traffic through the Fortinet Firewall, with no direct internet access to the Function App.
- **Non-SSL**: You’re using HTTP to avoid certificate management, suitable only for testing due to security risks.

### Azure Application Gateway Overview
The Azure Application Gateway is a layer 7 (application layer) load balancer that routes HTTP/HTTPS traffic based on URL paths, hostnames, or other rules. It includes features like Web Application Firewall (WAF), session affinity, and health monitoring. For your scenario, it acts as the public entry point, forwarding HTTP requests to the Function App’s private endpoint via the Fortinet Firewall.

#### Key Application Gateway Components
1. **Frontend IP Configuration**: Defines the IP address (public or private) where the Application Gateway receives incoming traffic.
2. **Listener**: Listens for incoming requests on a specific IP, port, and protocol (e.g., HTTP port 80).
3. **Backend Pool**: Specifies the target(s) where traffic is sent (e.g., Function App’s private IP or hostname).
4. **HTTP Settings**: Configures how traffic is forwarded to the backend (e.g., protocol, port, timeout).
5. **Health Probe**: Monitors backend health to ensure traffic is sent only to healthy targets.
6. **Routing Rule**: Maps listeners to backend pools and HTTP settings to route traffic.
7. **Web Application Firewall (WAF)** (optional): Inspects traffic for common vulnerabilities.
8. **Subnet and UDR**: Ensures traffic to the backend is routed correctly (e.g., via the Fortinet Firewall).

Below, I’ll explain each component, its configuration, why it works, and how it fits into your architecture.

---

### Detailed Explanation of Application Gateway Components and Configurations

#### 1. Frontend IP Configuration
- **Purpose**: Defines the IP address where clients (e.g., internet users) send requests to the Application Gateway.
- **Configuration**:
  - **Type**: Public IP (for internet-facing access).
  - **Setup**: In the Azure Portal, go to Application Gateway → Frontend IP Configurations → Add. Select a public IP address (static or dynamic, e.g., `20.50.60.70`).
  - **Example**: Public IP named `AppGwPublicIP` with DNS `api.contoso.com` (optional).
- **Why It Works**:
  - The public IP allows external clients to reach the Application Gateway over the internet.
  - For HTTP, clients send requests to `http://api.contoso.com` or `http://20.50.60.70`.
  - The Application Gateway binds this IP to a listener (see below) to process incoming HTTP traffic.
- **How It Fits**:
  - This is the entry point for internet traffic, ensuring all requests hit the Application Gateway before being routed to the Function App’s private endpoint.

#### 2. Listener
- **Purpose**: Listens for incoming HTTP requests on a specific IP, port, and protocol.
- **Configuration**:
  - **Name**: `FunctionAppListener`.
  - **Frontend IP**: Public IP (e.g., `20.50.60.70`).
  - **Protocol**: HTTP (port 80, no SSL since you’re avoiding certificates).
  - **Hostname**: `api.contoso.com` (optional, for host-based routing; leave blank for IP-based access).
  - **Setup**: Go to Application Gateway → Listeners → Add. Select HTTP, port 80, and the public IP. Set hostname if using a custom domain.
- **Why It Works**:
  - The listener captures HTTP requests on port 80 (e.g., `http://api.contoso.com/api/health`).
  - It directs these requests to a routing rule (see below) for further processing.
  - Using HTTP eliminates the need for an SSL certificate, simplifying setup for testing.
- **How It Fits**:
  - The listener ensures external HTTP requests are received and passed to the routing rule, which forwards them to the Function App via the Fortinet Firewall.
- **Note**: Without SSL, traffic is unencrypted, making it vulnerable to interception. For production, use HTTPS with a certificate.

#### 3. Backend Pool
- **Purpose**: Defines the target(s) where the Application Gateway sends traffic (e.g., the Function App’s private endpoint).
- **Configuration**:
  - **Name**: `FunctionAppBackend`.
  - **Target**: Function App’s hostname (`myfunctionapp.azurewebsites.net`) or private IP (e.g., `10.2.1.5`).
  - **Setup**:
    - Go to Application Gateway → Backend Pools → Add.
    - Add the Function App’s hostname or private IP.
    - If using hostname, ensure the Private DNS Zone (`privatelink.azurewebsites.net`) resolves `myfunctionapp.azurewebsites.net` to `10.2.1.5` in the Application Gateway’s VNet (via peering).
  - **Example**: Backend pool targets `myfunctionapp.azurewebsites.net`, resolved to `10.2.1.5`.
- **Why It Works**:
  - The backend pool specifies the Function App’s private endpoint as the destination.
  - Using the hostname with Private DNS allows the Application Gateway to resolve the Function App to its private IP, ensuring traffic stays within the VNet and avoids public internet.
  - The private endpoint ensures no public access to the Function App, aligning with your no-internet-traffic policy.
- **How It Fits**:
  - Traffic from the Application Gateway is sent to the Function App’s private IP (via the Fortinet Firewall), ensuring secure and controlled routing.

#### 4. HTTP Settings
- **Purpose**: Configures how the Application Gateway communicates with the backend (e.g., protocol, port, timeouts).
- **Configuration**:
  - **Name**: `FunctionAppHttpSettings`.
  - **Protocol**: HTTP (port 80).
  - **Enable “Use for App Service”**: Simplifies configuration for Azure Function Apps/App Services.
  - **Host Name Override**: Set to `myfunctionapp.azurewebsites.net` (ensures the correct host header is sent to the Function App).
  - **Timeouts**: Default (e.g., 20 seconds request timeout).
  - **Setup**: Go to Application Gateway → HTTP Settings → Add. Select HTTP, port 80, enable “Use for App Service,” and set host name override.
- **Why It Works**:
  - HTTP on port 80 matches the non-SSL setup, ensuring compatibility with the Function App’s private endpoint.
  - “Use for App Service” automatically handles Azure-specific headers and authentication for Function Apps, reducing configuration errors.
  - Host name override ensures the Function App receives the correct host header (`myfunctionapp.azurewebsites.net`), which is required for proper routing and response handling.
  - Default timeouts are sufficient for most API calls, but can be adjusted for long-running requests.
- **How It Fits**:
  - The HTTP settings ensure the Application Gateway sends HTTP traffic to the Function App’s private endpoint correctly, routed through the Fortinet Firewall.

#### 5. Health Probe
- **Purpose**: Monitors the backend’s health to ensure traffic is sent only to healthy targets.
- **Configuration**:
  - **Name**: `FunctionAppHealthProbe`.
  - **Protocol**: HTTP.
  - **Host**: `myfunctionapp.azurewebsites.net` (or private IP `10.2.1.5`).
  - **Path**: `/api/health` (requires a Function App endpoint returning HTTP 200).
  - **Interval**: 30 seconds.
  - **Timeout**: 30 seconds.
  - **Unhealthy Threshold**: 3 (marks backend unhealthy after 3 failed attempts).
  - **Setup**: Go to HTTP Settings → Add Probe (or create separately under Probes). Set HTTP, port 80, and the health path.
- **Why It Works**:
  - The probe periodically sends HTTP GET requests to `/api/health` to check if the Function App is responsive.
  - A 200 OK response indicates the Function App is healthy, allowing the Application Gateway to send traffic to it.
  - Using the hostname ensures the probe resolves to the private IP via Private DNS, keeping traffic within the VNet.
  - The interval and threshold settings balance responsiveness and stability, avoiding false negatives during brief outages.
- **How It Fits**:
  - The health probe ensures the Application Gateway only routes traffic to a functioning Function App, preventing errors if the backend is down.
  - It aligns with your architecture by using the private endpoint’s IP, routed via the Fortinet Firewall.

#### 6. Routing Rule
- **Purpose**: Maps incoming requests (via the listener) to the backend pool using the HTTP settings.
- **Configuration**:
  - **Name**: `FunctionAppRule`.
  - **Type**: Basic (single listener to single backend).
  - **Listener**: `FunctionAppListener` (HTTP, port 80).
  - **Backend Pool**: `FunctionAppBackend`.
  - **HTTP Settings**: `FunctionAppHttpSettings`.
  - **Setup**: Go to Application Gateway → Rules → Add (Basic Rule). Associate the listener, backend pool, and HTTP settings.
- **Why It Works**:
  - The routing rule ties together the listener (public entry point), backend pool (Function App), and HTTP settings (communication protocol).
  - For a request to `http://api.contoso.com/api/health`, the listener captures it, and the rule forwards it to the Function App’s private IP using HTTP settings.
  - The basic rule is sufficient for your single-backend scenario, ensuring straightforward routing.
- **How It Fits**:
  - The rule ensures external HTTP requests are correctly routed to the Function App’s private endpoint, maintaining the traffic flow through the Fortinet Firewall.

#### 7. Web Application Firewall (WAF) (Optional)
- **Purpose**: Inspects incoming traffic for common vulnerabilities (e.g., SQL injection, XSS).
- **Configuration**:
  - **Mode**: Prevention (blocks malicious requests) or Detection (logs only, for testing).
  - **Ruleset**: OWASP 3.2 (standard web security rules).
  - **Custom Rules**: Exclude specific rules if your API triggers false positives (e.g., for complex JSON payloads).
  - **Setup**: Go to Application Gateway → Web Application Firewall → Settings. Enable WAF, select Prevention mode, and configure rules.
- **Why It Works**:
  - WAF scans HTTP requests for patterns of attacks, blocking malicious traffic before it reaches the Function App.
  - Prevention mode ensures security, while Detection mode is useful for testing to avoid blocking legitimate requests.
  - Without SSL, WAF still provides value but is less effective, as traffic is unencrypted and vulnerable to interception.
- **How It Fits**:
  - WAF adds a security layer at the Application Gateway, protecting the Function App’s API from common web attacks.
  - It’s optional but recommended, even in a test environment, to validate rule configurations.

#### 8. Subnet and User-Defined Route (UDR)
- **Purpose**: Ensures traffic from the Application Gateway to the Function App is routed through the Fortinet Firewall.
- **Configuration**:
  - **Subnet**: The Application Gateway resides in a dedicated subnet (e.g., `10.1.0.0/24`) in its VNet, peered to the hub VNet.
  - **UDR**:
    - **Route Name**: `ToFunctionApp`.
    - **Destination**: Function App’s subnet (e.g., `10.2.1.0/24`).
    - **Next Hop Type**: Virtual Appliance.
    - **Next Hop IP**: Fortinet Firewall’s internal IP (e.g., `10.0.0.4`).
    - **Setup**: Go to Route Tables → Create, add the route, and associate it with the Application Gateway’s subnet.
- **Why It Works**:
  - The UDR overrides default Azure routing, forcing traffic from the Application Gateway’s subnet to the Function App’s private IP to go through the Fortinet Firewall.
  - VNet peering between the Application Gateway’s VNet and the hub VNet allows traffic to reach the firewall.
  - The firewall inspects and forwards traffic to the Function App’s subnet (peered from hub to spoke), ensuring controlled routing.
- **How It Fits**:
  - The UDR enforces your hub-and-spoke model, ensuring all traffic passes through the Fortinet Firewall for inspection, aligning with your no-internet-traffic policy.

---

### Why the Configuration Works
The Application Gateway components work together to achieve your goal:
1. **Public Access**: The frontend IP and listener expose the API publicly over HTTP (e.g., `http://api.contoso.com`), making it accessible to internet clients.
2. **Private Backend**: The backend pool targets the Function App’s private endpoint (`10.2.1.5`), resolved via Private DNS, ensuring no public exposure of the Function App.
3. **Controlled Routing**: The UDR and Fortinet Firewall policies ensure traffic flows through the hub, allowing inspection and enforcing your security model.
4. **Health Monitoring**: The health probe ensures reliability by routing traffic only to a healthy Function App.
5. **Simplified Non-SSL**: Using HTTP eliminates certificate management, making setup faster for testing, though it sacrifices encryption.

The configuration leverages Azure’s networking features (VNet peering, Private DNS, private endpoints) and the Fortinet Firewall’s traffic control to create a secure, controlled path from the internet to the Function App, despite using HTTP.

---

### How the Components Interact
1. **Request Flow**:
   - A client sends `http://api.contoso.com/api/health` to the Application Gateway’s public IP (`20.50.60.70`).
   - The listener (`FunctionAppListener`) captures the HTTP request on port 80.
   - The routing rule (`FunctionAppRule`) maps the request to the backend pool (`FunctionAppBackend`) using HTTP settings (`FunctionAppHttpSettings`).
   - The Application Gateway resolves `myfunctionapp.azurewebsites.net` to `10.2.1.5` via Private DNS.
   - The UDR routes the request from the Application Gateway’s subnet (`10.1.0.0/24`) to the Fortinet Firewall (`10.0.0.4`).
   - The firewall forwards the request to the Function App’s private endpoint (`10.2.1.5:80`).
   - The Function App processes the request and sends the response back through the firewall and Application Gateway to the client.
2. **Health Monitoring**:
   - The health probe periodically sends `http://myfunctionapp.azurewebsites.net/api/health` to `10.2.1.5:80`, routed via the firewall.
   - A 200 OK response keeps the backend marked as healthy.
3. **WAF (if enabled)**:
   - Inspects incoming requests for malicious patterns, blocking attacks before they reach the Function App.

---

### Updated Verification Steps
To ensure each Application Gateway component is configured correctly, here are detailed testing procedures, tailored to the non-SSL setup and focusing on component-specific validation.

#### **Test 1: Frontend IP and Listener**
- **Goal**: Verify the Application Gateway receives HTTP requests on its public IP.
- **Steps**:
  1. From an external machine, run: `curl http://<public-ip>/` (e.g., `curl http://20.50.60.70/`).
     - Expected: Response from the Function App (e.g., HTTP 200 for `/api/health`) or a default error if no path is specified.
  2. If using a hostname, run: `curl http://api.contoso.com/`.
     - Expected: Same response, assuming DNS is configured.
  3. Check Application Gateway logs:
     - Query: `AzureDiagnostics | where ResourceType == "APPLICATIONGATEWAYS" and OperationName == "ApplicationGatewayAccess"`.
     - Expected: Logs show HTTP requests hitting the listener.
- **Troubleshooting**:
  - If connection fails, verify the public IP is associated with the Application Gateway.
  - Ensure the listener is set to HTTP, port 80, and no SSL certificate is required.
  - Check NSGs on the Application Gateway’s subnet for port 80 access.

#### **Test 2: Backend Pool and HTTP Settings**
- **Goal**: Confirm the Application Gateway can reach the Function App’s private endpoint over HTTP.
- **Steps**:
  1. Check backend health:
     - Go to Application Gateway → Backend Health.
     - Expected: `FunctionAppBackend` shows “Healthy” for `myfunctionapp.azurewebsites.net` or `10.2.1.5`.
  2. Deploy a test VM in the Application Gateway’s VNet.
  3. From the VM, run: `curl http://myfunctionapp.azurewebsites.net/api/health` or `curl http://10.2.1.5/api/health`.
     - Expected: HTTP 200 response, routed via the Fortinet Firewall.
  4. Verify host name override:
     - Temporarily disable host name override in HTTP settings and retry the request.
     - Expected: Request may fail if the Function App expects the correct host header.
- **Troubleshooting**:
  - If backend is unhealthy, verify the health probe path (`/api/health`) and port 80.
  - Ensure Private DNS resolves `myfunctionapp.azurewebsites.net` to `10.2.1.5` in the Application Gateway’s VNet.
  - Check UDR and firewall policies for connectivity to `10.2.1.5`.

#### **Test 3: Health Probe**
- **Goal**: Validate the health probe correctly monitors the Function App.
- **Steps**:
  1. Check probe status:
     - Go to Application Gateway → Backend Health.
     - Expected: Probe status is “Healthy” with HTTP 200 for `/api/health`.
  2. Temporarily modify the Function App to return HTTP 500 for `/api/health`.
     - Expected: Backend becomes “Unhealthy” after ~90 seconds (3 x 30s interval).
  3. Revert the Function App to return HTTP 200 and recheck.
     - Expected: Backend returns to “Healthy.”
  4. Verify probe logs:
     - Check Application Gateway logs for probe requests: `AzureDiagnostics | where OperationName == "ApplicationGatewayHealth"`.
- **Troubleshooting**:
  - Ensure the Function App has a `/api/health` endpoint returning HTTP 200.
  - Verify probe settings match HTTP settings (HTTP, port 80, correct host).
  - Check firewall logs for probe traffic to `10.2.1.5:80`.

#### **Test 4: Routing Rule**
- **Goal**: Ensure the routing rule correctly forwards requests to the Function App.
- **Steps**:
  1. From an external machine, run: `curl http://api.contoso.com/api/health`.
     - Expected: HTTP 200 response from the Function App.
  2. Temporarily disassociate the routing rule (delete or modify it).
     - Retry the request: Expected: Request fails (e.g., HTTP 502 or timeout).
  3. Re-associate the rule and retry.
     - Expected: Request succeeds.
- **Troubleshooting**:
  - Verify the rule links the correct listener, backend pool, and HTTP settings.
  - Check Application Gateway logs for routing errors.

#### **Test 5: WAF (if enabled)**
- **Goal**: Confirm WAF inspects and blocks malicious HTTP traffic.
- **Steps**:
  1. Send a malicious request: `curl http://api.contoso.com/api/health?test=<script>`.
     - Expected: HTTP 403 (blocked by WAF in Prevention mode).
  2. Check WAF logs:
     - Query: `AzureDiagnostics | where ResourceType == "APPLICATIONGATEWAYS" and OperationName == "ApplicationGatewayFirewall"`.
     - Expected: Logs show blocked request with rule ID (e.g., OWASP 942100).
  3. Test legitimate request: `curl http://api.contoso.com/api/health`.
     - Expected: HTTP 200 (allowed).
- **Troubleshooting**:
  - If legitimate requests are blocked, exclude specific WAF rules or switch to Detection mode.
  - Verify WAF is enabled and configured with OWASP 3.2 ruleset.

#### **Test 6: UDR and Firewall Routing**
- **Goal**: Validate traffic is routed through the Fortinet Firewall.
- **Steps**:
  1. Check Fortinet Firewall logs for traffic from `10.1.0.0/24` (Application Gateway) to `10.2.1.5` (Function App) on port 80.
     - Expected: Logs show allowed traffic.
  2. Temporarily remove the UDR from the Application Gateway’s subnet.
     - Send a request: `curl http://api.contoso.com/api/health`.
     - Expected: Request fails (traffic doesn’t reach the Function App).
  3. Re-apply the UDR and retry.
     - Expected: Request succeeds.
  4. Disable the firewall’s ingress policy and retry.
     - Expected: Request fails.
- **Troubleshooting**:
  - Verify UDR destination (`10.2.1.0/24`) and next hop (`10.0.0.4`).
  - Check firewall policies for port 80 traffic.
  - Ensure VNet peering is configured correctly.

#### **Test 7: End-to-End Connectivity**
- **Goal**: Confirm the full HTTP traffic flow.
- **Steps**:
  1. Run: `curl http://api.contoso.com/api/health`.
     - Expected: HTTP 200 response.
  2. Check logs:
     - Application Gateway: Confirm request hits backend.
     - Fortinet Firewall: Verify bidirectional traffic.
  3. Attempt direct access: `curl http://myfunctionapp.azurewebsites.net/api/health`.
     - Expected: Connection timeout (private endpoint blocks public access).
- **Troubleshooting**:
  - Isolate issues using Tests 1–6.
  - Verify Private DNS and VNet peering.

---

### Additional Notes
- **Security Warning**: HTTP is insecure for production. Transition to HTTPS with certificates (e.g., Let’s Encrypt, Azure Key Vault) as soon as testing is complete.
- **Health Endpoint**: Ensure the Function App has a `/api/health` endpoint (e.g., a simple HTTP-triggered function returning `{"status":"healthy"}` with HTTP 200).
- **Scalability**: The Application Gateway v2 SKU (Standard_v2 or WAF_v2) supports autoscaling, suitable for variable API traffic.
- **Cost**: Monitor Application Gateway usage to avoid unnecessary costs (e.g., oversized WAF tier).
- **ARM Template Example** (simplified for HTTP):
  ```json
  {
    "type": "Microsoft.Network/applicationGateways",
    "apiVersion": "2023-04-01",
    "name": "myAppGateway",
    "location": "eastus",
    "properties": {
      "sku": { "name": "Standard_v2", "tier": "Standard_v2" },
      "frontendIPConfigurations": [
        {
          "name": "appGwPublicFrontendIp",
          "properties": {
            "publicIPAddress": { "id": "[resourceId('Microsoft.Network/publicIPAddresses', 'AppGwPublicIP')]" }
          }
        }
      ],
      "frontendPorts": [{ "name": "port_80", "properties": { "port": 80 } }],
      "backendAddressPools": [
        {
          "name": "FunctionAppBackend",
          "properties": { "backendAddresses": [{ "fqdn": "myfunctionapp.azurewebsites.net" }] }
        }
      ],
      "backendHttpSettingsCollection": [
        {
          "name": "FunctionAppHttpSettings",
          "properties": {
            "port": 80,
            "protocol": "Http",
            "hostName": "myfunctionapp.azurewebsites.net",
            "probe": { "id": "[concat(resourceId('Microsoft.Network/applicationGateways', 'myAppGateway'), '/probes/FunctionAppHealthProbe')]" }
          }
        }
      ],
      "httpListeners": [
        {
          "name": "FunctionAppListener",
          "properties": {
            "frontendIPConfiguration": { "id": "[concat(resourceId('Microsoft.Network/applicationGateways', 'myAppGateway'), '/frontendIPConfigurations/appGwPublicFrontendIp')]" },
            "frontendPort": { "id": "[concat(resourceId('Microsoft.Network/applicationGateways', 'myAppGateway'), '/frontendPorts/port_80')]" },
            "protocol": "Http"
          }
        }
      ],
      "requestRoutingRules": [
        {
          "name": "FunctionAppRule",
          "properties": {
            "ruleType": "Basic",
            "httpListener": { "id": "[concat(resourceId('Microsoft.Network/applicationGateways', 'myAppGateway'), '/httpListeners/FunctionAppListener')]" },
            "backendAddressPool": { "id": "[concat(resourceId('Microsoft.Network/applicationGateways', 'myAppGateway'), '/backendAddressPools/FunctionAppBackend')]" },
            "backendHttpSettings": { "id": "[concat(resourceId('Microsoft.Network/applicationGateways', 'myAppGateway'), '/backendHttpSettingsCollection/FunctionAppHttpSettings')]" }
          }
        }
      ],
      "probes": [
        {
          "name": "FunctionAppHealthProbe",
          "properties": {
            "protocol": "Http",
            "host": "myfunctionapp.azurewebsites.net",
            "path": "/api/health",
            "interval": 30,
            "timeout": 30,
            "unhealthyThreshold": 3
          }
        }
      ]
    }
  }
  ```

If you need further details (e.g., CLI commands, WAF rule exclusions, or SSL transition steps), let me know!
