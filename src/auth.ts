import { Request, Response } from "express";
import { OAuthGlobalClient } from "./oAuthGlobalClient.js";

function getOp(req: Request): string {
  const isMessageEndpoint = req.path.endsWith('/message');
  if (!isMessageEndpoint){ 
    return 'NON_MCP';
  } else {
    // Get the operation from the jsonRpc message
    let op = req.body.method;
    const toolName = req.body.params?.name;
    if (toolName) {
      op = `${op}:${toolName}`
    }
    if (!op) {
      throw new Error('No operation found in request');
    }
    return op;
  }
}

// opPrices is experimental: The names of tools that will be charged for if PayMcp is used. 
// If not provided, all tools will be charged at the amount specified in the authorizationServerUrl's amount field
// If any are provided, all unlisted tools will be charged at 0
export function requireOAuthUser(tokenIntrospectionServerUrl: string, oauthClient: OAuthGlobalClient, opPrices?: {[key:string]: number}): (req: Request, res: Response) => Promise<string | undefined> {
  return async (req: Request, res: Response): Promise<string | undefined> => {
    const protocol = process.env.NODE_ENV === 'development' ? 'http' : 'https';
    const protectedResourceMetadataUrl = `${protocol}://${req.host}/.well-known/oauth-protected-resource${req.path}`;

    // Extract the Bearer token from the Authorization header
    const authHeader = req.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.log('[auth] No authorization header found');
      // Set the WWW-Authenticate header for 401 responses as per PRM spec
      res.set('WWW-Authenticate', protectedResourceMetadataUrl);
      res.status(401).json({ error: 'invalid_request', error_description: 'No token provided' });
      return undefined;
    }

    const token = authHeader.substring(7);
    
    try {
      // Perform token introspection
      let additionalParameters = {};
      const op = getOp(req);
      // If they've specified any prices, we pass charge for everything
      // Anything they didn't specify is 0
      // TODO: Revisit the implicit 0 pricing of unspecified operations
      if (opPrices) {
        // We don't just set the amount because according to the docs, we can't change existing parameters
        // https://github.com/panva/oauth4webapi/blob/main/docs/interfaces/IntrospectionRequestOptions.md
        // We can't just strip the amount parameter just for the token introspection request, because that 
        // has to be reflected in /.well-known/oauth-protected-resource, (which is annoying but possible),
        // AS WELL as in the AS's /.well-known/oauth-authorization-server, (which would require the AS to 
        // make a decision for all clients about whether they have to send an amount parameter or not).
        additionalParameters = { charge: opPrices[op] || 0 };
      }
      console.log('[auth] Introspecting token for op:', op, 'with additional parameters:', additionalParameters);
      const introspectionResult = await oauthClient.introspectToken(tokenIntrospectionServerUrl, token, additionalParameters);
      
      if (!introspectionResult.active) {
        console.log('[auth] Token is not active');
        res.set('WWW-Authenticate', protectedResourceMetadataUrl);
        res.status(401).json({ error: 'invalid_token', error_description: 'Token is not active' });
        return undefined;
      }
      
      // Return the subject (user ID) from the introspection response
      return introspectionResult.sub;
    } catch (error) {
      console.error('[auth] Error during token introspection:', error);
      res.status(500).json({ error: 'server_error', error_description: 'An internal server error occurred' });
      return undefined;
    }
  };
}