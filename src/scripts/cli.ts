import { PayMcpClient, SolanaPaymentMaker, SqliteOAuthDb } from '../index';
import 'dotenv/config';

async function main() {
  console.log('Starting PayMcpClient example...');
  
  // Create a SQLite database instance
  const db = new SqliteOAuthDb(':memory:');
  
  // Create a new OAuth client
  const solana = new SolanaPaymentMaker(process.env.SOLANA_ENDPOINT!, process.env.SOLANA_PRIVATE_KEY!);
  const client = new PayMcpClient("local", db, true, {"solana": solana});

  try {
    // Make a request to a protected resource
    // This will automatically handle the OAuth flow if needed
    const data = await client.fetch(
      'http://localhost:3001',
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
            "arguments": {
              //"executionId": "development-paymcp-example-localhost-80661f45-ccb9-49f7-bd64-3e5ff0de8d55|asdfasdf"
            },
            //"name": "topHackerNewsStoriesWorkflow-results"
            "name": "checkBalance" // browser-use
          }
        })
      }
    );
    
    console.log('Response:', data);
    console.log('Body:', await data.text());
    console.log('\nPayMcpClient example completed successfully!');
  } catch (error) {
    if (error instanceof Error) {
      console.error('Error during OAuth flow:', error.message);
    } else {
      console.error('Unknown error during OAuth flow:', error);
    }
  } finally {
    // Close the database connection
    await db.close();
    process.exit(0);
  }
}

// Run the example
main().catch(console.error); 
