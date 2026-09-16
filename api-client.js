//api-client.js
// API Client Node
module.exports = function (RED) {
  "use strict";
  const axios = require("axios");
  function ApiClientNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;
    // Get the config node
    // console.log(config)
    // node.log(`PL API Client initiating`);
    // node.log(`Secret Manager Node id: ${config.secretMgr}`);
    const secretMgr = RED.nodes.getNode(config.secretMgr);
    const flowContext = this.context().flow;

    // Node Settings
    node.method = config.method || "GET";
    node.service = config.service || "mes-api";
    node.overridePayload = config.overridePayload || false;
    node.includeResponseObject = (process.env.NODE_ENV === "dev" && config.extraRespInfo);
    
    node.location = secretMgr.loc
    node.environment = secretMgr.env
    // node.location = process.env.LOC.toLowerCase();
    // node.environment = process.env.ENV.toLowerCase();

    // node.log(Object.keys(secretMgr))

    // node.endpoint = config.endpoint;
    node.log(`Credential Source: ${secretMgr.source}`)
    node.log(`${node.location} --- ${node.environment}`)
    node.connected = false;
    // node.log(Object.keys(secretMgr))

    // if(node.service && node.location && node.endpoint){
    //   node.url = parseUrl({
    //     service: node.service,
    //     location: node.location,
    //     endpoint: node.endpoint
    //   });
    // } else {
    //   node.url = "";
    // }
    // node.log(`Node Url = ${node.url}`);

    // Check if config exists
    if (!secretMgr) {
      node.status({
        fill: "red",
        shape: "ring",
        text: "Missing configuration",
      });
      return;
    }

    // Set initial status
    node.status({ fill: "yellow", shape: "dot", text: "Initializing..." });
    
    // node.debug("Creating Thycotic Connection");
    node.connected = secretMgr.connect();

    // node.apiClient = axios.create({
    //   headers: { "X-Script-Name": "node-red-api-client" },
    //   timeout: 10000,
    // });

    const options = {
      headers: { "X-Script-Name": "node-red-api-client" },
      timeout: 20000
    }

    node.apiClient = flowContext.get("plClient") || null

    if(node.apiClient==null){
      node.debug("No client in flow context. Creating new client");
      node.apiClient = axios.create(options)
      flowContext.set("plClient", node.apiClient)
    }

    //For Debugging
    node.apiClient.interceptors.request.use(async function(config){
      node.trace(`Firing request: ${config.method} --- ${config.url}`)
      return config
    })

    node.apiClient.interceptors.response.use(async function(response){
      let respUrl = await response?.request?.res.responseUrl;
      node.trace(`Received response: ${response?.status} --- ${respUrl}`);
      return response
    }, async function(error){
      node.warn(`Error with response: ${error.message}`)
      return Promise.reject(error);
    })
    
    node.retieveToken = function(environment){
      let envStr = environment ? `${environment}` : secretMgr.environment;

      const now = Date.now();
      const flowJwt = { token:flowContext.get(`${envStr}-jwt`), tokenExpiry:flowContext.get(`${envStr}-jwtExpiry`) }

      // If token exists and is not expired, return it
      if (node.token && node.tokenExpiry && now < node.tokenExpiry) {
        return true;
      } else if (flowJwt && flowJwt.token && flowJwt.tokenExpiry && now < flowJwt.tokenExpiry){
        node.debug("Using existing jwt in flow context")
        node.token = flowJwt.token;
        node.tokenExpiry = flowJwt.tokenExpiry;
        return true
      }
      return null
    }

    node.storeToken = function(environment){
      let envStr = environment ? `${environment}` : secretMgr.environment;
      flowContext.set([`${envStr}-jwt`, `${envStr}-jwtExpiry`], [node.token, node.tokenExpiry]);
      node.debug(`JWT stored in flow context`);

      return null
    }

    node.getToken = async function (){
      if(node.retieveToken()){
        return node.token
      }

      const now = Date.now();

      // const options = `Bearer ${await secretMgr.getCredentials()}`
      const secrets = await node.getCredentials();
  
      const options = {
        method: "POST",
        url: node.getIdentityUrl() + "/connect/token",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept": "application/json",
        },
        data: {
          grant_type: "client_credentials",
          client_id: secrets.client_id,
          client_secret: secrets.client_secret,
        }
      }
      
      const response = await node.apiClient.request(options)

      if (response.data && response.data.access_token) {
        node.token = response.data.access_token;
        // Set expiry to 5 minutes before actual expiry to be safe
        node.tokenExpiry = Date.now() + ((response.data.expires_in || 3600) - 120) * 1000;
        node.storeToken();

        node.log("API token refreshed");
        return node.token;
      } else {
        node.error("Invalid token response format");
        return null;
      }
    }
    
    node.getAuthHeader= async function(){
      const token = await node.getToken()
      return `Bearer ${token}`
    }

    node.getCredentials = async function(){
      if(node.creds){
        return node.creds
      }
      await node.connected;
      // const clientId = await secretMgr.getSecretField(secretMgr.secretName, "ClientID");
      // const clientSecret = await secretMgr.getSecretField(secretMgr.secretName, "ClientSecret");
      const clientId = await secretMgr.getSecretField(secretMgr.credentials.secretName, "ClientID");
      const clientSecret = await secretMgr.getSecretField(secretMgr.credentials.secretName, "ClientSecret");
      
      node.creds = { client_id: clientId, client_secret: clientSecret };
      return node.creds;
    }

    node.getIdentityUrl = function(){
      return secretMgr.credentials.identityUrl
    }

    async function makeRequest(axiosOpts){
      const authHeader = {
        Authorization: await node.getAuthHeader()
      }

      var options = {
        method: axiosOpts.method,
        url: axiosOpts.url,
        headers: {...axiosOpts.headers,...authHeader},
        data: axiosOpts?.data || {}
      }
      return node.apiClient.request(options)
    }

    function parseRequestParams(msg){
      let parsedBody = {}
            
      if(Object.keys(msg).includes('request')){
        let parsedUrl = parseUrl(msg.request);
        let parsedMethod = parseMethod(msg.request);
        
        parsedBody = msg.request?.body
                ? msg.request.body 
                : parsedBody;

        // parsedMethod = msg.request?.method
        //               ? msg.request.method.toUpperCase() 
        //               : parsedMethod;
        // Axios serializes the "body" object automatically
        // parsedBody = JSON.stringify(msg.request?.body)
        return {
          url: parsedUrl,
          method: parsedMethod,
          body: parsedBody
        }
      }
    }
      // if (node.url){
      //   return {
      //     url: node.url,
      //     method: node.method,
      //     body: parsedBody,
      //   }

      // }

    function parseUrl(params) {
      if (params?.url) {
        return params.url;
      }else if(params?.endpoint){
        // const { service=node.service, location=node.location, endpoint } = params;
        // node.debug(JSON.stringify(params))
        // node.debug(`https://${service}.${location}.${environment}.protolabs.io${endpoint}`);
        // return `https://${service}.${location}.${environment}.protolabs.io${endpoint}`;
        return `https://${params?.service || node.service}.${node.location}.${node.environment}.protolabs.io${params.endpoint}`;
      }
      node.error("No URL or endpoint parameter detected in msg.request")
     }


    function parseMethod(params){
      // const parsedMethod = params?.method || node.method || "GET";
      const parsedMethod = params?.method || "GET";
      if (parsedMethod !== "GET" && parsedMethod !== "POST") {
        throw new Error(
          `Unsupported method: ${parsedMethod}. Only GET and POST are supported.`,
        );
      }

      return parsedMethod

    }

    // Handle incoming messages
    node.on("input", async function (msg, send, done) {
      const req = parseRequestParams(msg);
      // node.log(`Received msg. Req: ${JSON.stringify(req)}`)
      // node.log(`${req.url}`)
      try {
        const regex = /\/api\/v\d\/([^\/]+).*?\/([^\/?]+)(?:\?.*)?$/;
        // const charLimit = 15
        let statusText = req.url.match(/\/api\/v\d(.{0,15})/g) || req.url.match(/\/api(.{0,15})/g)
        
        // const match = req.url.match(regex);
        // if (match) {
        //   const [, firstSegment, lastSegment] = match;
        //   statusText = `/${firstSegment}/…/${lastSegment}`;
        // }

        
        node.status({
          fill: "blue",
          shape: "dot",
          text: `${req.method}: ${statusText}…`,
        });

        const options = {
          method: req.method,
          url: req.url,
          data: {},
        };

        if (req.method === "POST") {
            const payload = req.body;
            options.data = payload;
        }
        const response = await makeRequest(options);

        // Process response
        msg.response = {
          status: response.status,
          statusText: response.statusText,
        }

        if(node.includeResponseObject){
          msg.response.responseHeaders=response.headers
          msg.response.config= response.config,
          msg.response.additionalProps= {"req": Object.keys(response.request)}
        }

        if (node.overridePayload) {
            msg.payload = response.data;
        } else {
          msg.response.data = response.data;
        }
        
        node.status({
          fill: "green",
          shape: "dot",
          text: `${req.method} ${response.status}: ${statusText}…`,
        });

        // Clear msg.request property & send
        delete msg.request;
        send(msg);

        if (done) {
          done();
        }
      } catch (error) {
        node.status({ fill: "red", shape: "dot", text: error.message });

        if (error.response) {
          node.status({ fill: "red", shape: "dot", text: `${error.message}` });

          msg.response = {
              status_code: error.response.status,
              response_headers: error.response.headers,
              data: error.response.data,
          };
          send(msg); // Send even on error, so flow can handle error cases
        } else {
          // Something else went wrong
          msg.payload = { error: error.message };
        }

        // Signal done with error if available
        if (done) {
          done(error);
        } else {
          // For older versions of Node-RED
          node.error(error, msg);
        }
      }
    });

    // Set status based on config node status if available
    if (secretMgr?.status) {
      node.status(secretMgr.status);
    } else {
      node.status({ fill: "green", shape: "dot", text: "Ready" });
    }

  }

  RED.nodes.registerType("api-client", ApiClientNode);
};
