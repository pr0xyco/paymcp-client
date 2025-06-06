import { PayMcpClient, SolanaPaymentMaker, SqliteOAuthDb } from '../index';
import 'dotenv/config';

function validateEnv() {
  const requiredVars = ['SOLANA_ENDPOINT', 'SOLANA_PRIVATE_KEY'];
  const missing = requiredVars.filter(varName => !process.env[varName]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}\nPlease set them in your .env file or environment.`);
  }
}

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const url = args[0] || 'https://browser-use.corp.pr0xy.co';
  const toolName = args[1] || 'checkBalance';
  
  // Parse named arguments
  const namedArgs: Record<string, string> = {};
  for (let i = 2; i < args.length; i++) {
    const arg = args[i];
    const [key, value] = arg.split('=');
    if (key && value) {
      namedArgs[key] = value;
    }
  }

  return { url, toolName, namedArgs };
}

async function main() {
  console.log('Starting PayMcpClient example...');
  console.log('\nUsage:');
  console.log('Via npm: npm run cli:fetch [url] [toolName] [arg1=value1] [arg2=value2]');
  console.log('\nExample: npm run cli:fetch http://localhost:3001 checkBalance foo=bar\n');
  console.log('--------------------------------');
  
  const { url, toolName, namedArgs } = parseArgs();
  console.log(`Calling tool "${toolName}" at URL: ${url}`);
  if (Object.keys(namedArgs).length > 0) {
    console.log('With arguments:', namedArgs);
  }
  console.log('--------------------------------');
  
  // Create a SQLite database instance
  const db = new SqliteOAuthDb({
    dbPathOrDb: ':memory:', 
    encrypt: (data: string) => data, 
    decrypt: (data: string) => data
  });
  
  try {
    validateEnv();
    
    // Create a new OAuth client
    const solana = new SolanaPaymentMaker(process.env.SOLANA_ENDPOINT!, process.env.SOLANA_PRIVATE_KEY!);
    const client = new PayMcpClient({
      userId: "local",
      db,
      paymentMakers: {"solana": solana}
    });

    // Make a request to a protected resource
    // This will automatically handle the OAuth flow if needed
    const data = await client.fetch(
      url,
      {
        method: 'POST',
        headers: {
          'Accept': 'application/json, text/event-stream',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          "jsonrpc": "2.0",
          "id": 1,
          "method": "tools/call",
          "params": {
            "arguments": namedArgs,
            "name": toolName
          }
        })
      }
    );
    
    console.log('Response:', data);
    console.log('Body:', await data.text());
  } catch (error) {
    if (error instanceof Error) {
      console.error('Error:', error.message);
    } else {
      console.error('Unknown error:', error);
    }
  } finally {
    // Close the database connection
    await db.close();
    process.exit(0);
  }
}

// Run the example
main().catch(console.error); 
