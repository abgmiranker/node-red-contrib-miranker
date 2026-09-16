// API Configuration Node
module.exports = function (RED) {
  "use strict";
  const axios = require("axios");
  const os = require("os");
  const uuidv4 = require("uuid").v4;
  const fs = require("fs");

  function secureKeyReader(PATH) {
    let cachedKey = null;
    
    function readKeyFromFile() {
        return fs.readFileSync(PATH, 'utf8').trim();
    }
    
    return {
      getKey() { 
        if (!cachedKey) { 
          cachedKey = readKeyFromFile(); 
        } 
        return cachedKey; 
      },
      clearKey() { cachedKey = null; }
    };
  }

  function parseCredentials(node){
    const credentials = node.credentials
    const src = node.source

      if(process.env.NODE_ENV==="dev" && src=="manual"){
        let parsedCreds = {
          secretUrl: credentials.secretUrl || process.env[SECRET_URL],
          identityUrl: credentials.identityUrl
        };
        
        if(credentials.secretName && credentials.secretRule && credentials.secretKey){
          node.debug("Name, Rule, Key configured manually")
          parsedCreds.secretName = credentials.secretName;
          parsedCreds.secretRule = credentials.secretRule;
          parsedCreds.secretKey = credentials.secretKey;
        } else {
          node.debug(`Missing SECRET_NAME, SECRET_RULE, or SECRET_KEY. Using default environment variables`)
          parsedCreds.secretName = process.env[SECRET_NAME];
          parsedCreds.secretRule = process.env[SECRET_RULE];
          parsedCreds.secretKey = process.env[SECRET_KEY];
        }
        node.debug(JSON.stringify(parsedCreds))
        return parsedCreds

      } else {
        node.debug("Credentials sourced from default environment variables")
        if(!Object.keys(process.env).includes("THYCOTIC_KEY_PATH")){
          node.error("Missing THYCOTIC_KEY_PATH environment variable");
        }
        return {
          secretUrl: process.env[SECRET_URL],
          secretName: process.env[SECRET_NAME], 
          secretRule: process.env[SECRET_RULE],
          secretKey: secureKeyReader(process.env["THYCOTIC_KEY_PATH"]).getKey(),
          identityUrl: process.env[IDENTITY_URL]
        };
      }
  }

  function SecretMgrNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    //This is used to avoid init loop when credentials are incorrect
    node.init = { attempted: false, failed: false };


    if(process.env.NODE_ENV==="dev" && config.source!=="environment"){
      node.debug("~~~~ DEVELOPMENT MODE ~~~~")
      node.loc = config.location
                  ? config.location
                  : process.env.LOC.toLowerCase()
      node.env = config.environment
                  ? config.environment
                  : process.env.ENV.toLowerCase()
    } else {
      node.debug("#### PRODUCTION MODE ####");
      node.loc = process.env.LOC.toLowerCase()
      node.env = process.env.ENV.toLowerCase()
    }

    node.source = config.source;
    node.debug(`Credential Source: ${config.source}`)
    node.credentials = parseCredentials(this);

    // node.debug(`Configured for: ${node.loc} --- ${node.env}`)

    // Initialize token state
    node.token = null;
    node.tokenExpiry = null;
    node.sdkAcctId = null;
    node.sdkAcctSecret = null;

    // Create axios instance for auth requests
    node.secretsMgr = axios.create({
      baseURL: node.credentials.secretUrl,
      headers: { "X-Script-Name": "node-red-api-client" },
      timeout: 10000,
    });

    //Debugging tool. Executes just before sending any request
    node.secretsMgr.interceptors.request.use(function(config){
      node.trace(`Axios Requesting: ${config.method} --- ${node.credentials.secretUrl}${config.url}`);
      return config
    })

    //Debugging tool. Executes just after receiving any responses
    node.secretsMgr.interceptors.response.use(async function(response){
      let respUrl = await response?.request?.res.responseUrl;
      node.trace(`Received response: ${response?.status} --- ${respUrl.replace(node.credentials.secretUrl, "")}`);
      return response
    }, async function(error){
      node.debug(`Error in response: ${JSON.stringify(error)} `)
      return Promise.reject(error);
    })

    node.getAuthHeader= async function(){
      const token = await node.getToken()
      return `Bearer ${token}`
    }

    node.getToken = async function () {
      const now = Date.now();

      // If token exists and is not expired, return it
      if (node.token && node.tokenExpiry && now < node.tokenExpiry) {
        return node.token;
      }

      const tokenRequestBody = {
        grant_type: "client_credentials",
        client_id: "sdk-client-" + node.clientUUID,
        client_secret: node.sdkAcctSecret,
      };
      const options = {
        method:"post",
        url:"/oauth2/token",
        data: tokenRequestBody,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept-Encoding": "gzip, deflate",
        },
      };
      
      try {
        // Request new token using client credentials flow
        const response = await node.secretsMgr.request(options);

        if (response.data && response.data.access_token) {
          node.token = response.data.access_token;
          // Set expiry to 5 minutes before actual expiry for no reason
          node.tokenExpiry =
            now + ((response.data.expires_in || 3600) - 300) * 1000;

          node.debug("Secrets Server token acquired");
          return node.token;
        } else {
          node.error("Invalid token response format");
          return null;
        }
      } catch (error) {
        node.error(`Failed to acquire token: ${error.message}`);
        return null;
      }
    };

    node.initSdkAccount = async function(){
      if(node.sdkAcctId){
        node.debug("Client ID for SDK Account already exists. Overwriting...")
      }
      node.sdkAcctId = uuidv4();

      const key = node.credentials.secretKey;
      const hostname = os.hostname();
      const sdkCreate = {
        clientId: node.sdkAcctId,
        name: hostname,
        description: `Machine: ${hostname}, OS: ${os.type()} - ${process.version}`,
        ruleName: node.credentials.secretRule,
        onboardingKey: key,
      }

      const options = {
        method: "post",
        url: "/api/v1/sdk-client-accounts",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Connection": "keep-alive",
          "Accept-Encoding": "gzip, deflate",
        },
        data: sdkCreate
      }

      return await node.secretsMgr.request(options).then(resp => resp.data)
    };

    node.closeSdkAccount = async function(){
      if (node.sdkAcctId) {
        const token = await node.getToken()
        const options = {
          method: "post",
          url: `/api/v1/sdk-client-accounts/${node.sdkAcctId}/revoke`,
          data: null,
          headers:{
            Authorization: `Bearer ${token}`,
          }
        }
        try {
          const response = await node.secretsMgr.request(options);
          console.log(`Revoked SDK client account ${node.sdkAcctId} for rule '${node.credentials.secretRule}'. Response: '${response.status}'`);
        } catch (error) {
          console.log(`Failed to close Secret Server Manager: ${error.message}.`);
        } finally {
          // Clear token data
          node.token = null;
          node.tokenExpiry = null;
          node.sdkAcctId = null;
        }
      } else {
        node.warn("Warning. No Thycotic clienId Detected")
      }
    };

    node.connect = async function(){
      if(node.init.failed){
        node.warn("Secret Server Connection failed previously. Aborting")
        node.status({fill:"black",shape:"dot",text:"Config: Init failed. Restart flows"})
        return false
      } else {
        node.init.attempted = true;
        node.status({fill:"blue",shape:"ring",text:"Config: Initializing..."})
        node.debug("Establishing Thycotic Connection...");

        try {
          const responseData = await node.initSdkAccount()
          node.clientUUID = responseData.clientId
          node.sdkAcctSecret = responseData.clientSecret
          node.sdkAcctId = responseData.id
          node.status({});
          
          return true
        } catch (error) {
          node.status({fill:"red",shape:"dot",text:"Config: Error Initializing"});
          node.debug(error);
          node.error(`Unable to connect to Thycotic. Error: ${error.message}`);
          // node.debug(JSON.stringify(error));
          node.init.failed = true;
        }
      }
      return false
    }

    node.getSecretIdByName = async function(secretName){
      const options = {
        method: "get",
        url: `/api/v2/secrets?filter.includeInactive=false&filter.searchText=${secretName}`,
        headers: {
          Authorization: await node.getAuthHeader() 
        }
      }
      const data = await node.secretsMgr.request(options).then((resp) => resp.data);

      if(data?.records && data.records.length>0){
        return data.records[0].id;
      } else {
        node.error(`Could not find a secret named: '${secretName}'`);
        return ''
      }
    };
    
    node.getSecretField = async function(secretName, fieldName){
      const secretId = await node.getSecretIdByName(secretName);
      const options = {
        method: "get",
        url:`/api/v2/secrets/${secretId}`, 
        headers: {
          Authorization: await node.getAuthHeader() 
        }
      }
      var data = await node.secretsMgr.request(options).then( (resp) => resp.data)

      for (const item of data.items) {
        if (item.fieldName.toString().toLowerCase() === fieldName.toLowerCase()) {
          return item.itemValue;
        }
      }

      node.error(`Field '${fieldName}' not found in secret '${secretName}'`);
    };

    // Clean up on close - send request to close client account
    node.on("close", async function() {
      node.closeSdkAccount();
    });
  }


  RED.nodes.registerType("secret-manager", SecretMgrNode, {
    credentials:{
      secretUrl: { type: "text" },
      secretRule: { type: "text"},
      secretKey: { type: "text"},
      secretName: { type: "text"},
      identityUrl: { type: "text" }
    }
  });

  RED.httpAdmin.get('/node-env', function(req, res) {
    if(process.env.NODE_ENV==="dev"){
      res.json(process.env);
    } else {
      res.json({
        NODE_ENV: process.env.NODE_ENV,  
        ENV: process.env.ENV,
        LOC: process.env.LOC,
      });
    }
  });
};


//Constants
const ENV_OPTIONS = ["default", "sit", "staging", "qe", "prod"];
const SECRET_URL = "THYCOTIC_URL";
const SECRET_NAME = "THYCOTIC_SECRET_NAME";
const SECRET_KEY = "THYCOTIC_KEY";
// const KEY_PATH = "THYCOTIC_KEY_PATH";
const SECRET_RULE = "THYCOTIC_RULE";
const IDENTITY_URL = "URI_IDENTITY_INTERNAL";