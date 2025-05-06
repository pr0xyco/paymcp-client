import { Database } from 'sqlite3';
import { promisify } from 'util';
import path from 'path';
import fs from 'fs';
import { DEFAULT_ENCRYPTION_KEY_ENV_VAR, encrypt, decrypt } from '@longrun/crypto-utils/src/index';

/**
 * Type definition for client credentials
 */
export type ClientCredentials = {
  clientId: string,
  clientSecret: string,
  redirectUri: string
};

/**
 * Type definition for PKCE values
 */
export type PKCEValues = {
  codeVerifier: string,
  codeChallenge: string,
  resourceServerUrl: string
};

/**
 * Interface for the database that stores OAuth-related data
 */
export interface OAuthClientDb {
  /**
   * Get client credentials for a specific resource server
   * @param resourceServerUrl The URL of the resource server
   * @returns The client credentials or null if not found
   */
  getClientCredentials(resourceServerUrl: string): Promise<ClientCredentials | null>;

  /**
   * Save client credentials for a specific resource server
   * @param resourceServerUrl The URL of the resource server
   * @param credentials The client credentials
   */
  saveClientCredentials(
    resourceServerUrl: string,
    credentials: ClientCredentials
  ): Promise<void>;

  /**
   * Get the PKCE values for a specific authorization request
   * @param state The state parameter used in the authorization request
   * @returns The PKCE values or null if not found
   */
  getPKCEValues(state: string): Promise<PKCEValues | null>;

  /**
   * Save the PKCE values for a specific authorization request
   * @param state The state parameter used in the authorization request
   * @param values The PKCE values
   */
  savePKCEValues(
    state: string,
    values: PKCEValues
  ): Promise<void>;

  /**
   * Get the access token for a specific resource server
   * @param resourceServerUrl The URL of the resource server
   * @returns The access token or null if not found or expired
   */
  getAccessToken(resourceServerUrl: string): Promise<{
    accessToken: string,
    refreshToken?: string,
    expiresAt?: Date
  } | null>;

  /**
   * Save the access token for a specific resource server
   * @param resourceServerUrl The URL of the resource server
   * @param token The access token
   */
  saveAccessToken(
    resourceServerUrl: string,
    token: {
      accessToken: string,
      refreshToken?: string,
      expiresAt?: Date
    }
  ): Promise<void>;

  /**
   * Close the database connection
   */
  close(): Promise<void>
}

/**
 * SQLite implementation of OAuthClientDb
 */
export class SqliteOAuthClientDb implements OAuthClientDb {
  private db: Database
  private run: (sql: string, params: any[]) => Promise<void>
  private get: (sql: string, params: any[]) => Promise<any>
  private all: (sql: string, params: any[]) => Promise<any[]>
  private dbClose: () => Promise<void>
  private initialized = false
  private encryptionKey: string

  static getDefaultDbPath(): string {
    const dbDir = path.join(process.cwd(), 'db');
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }
    return path.join(dbDir, 'oauthClient.db');
  }

  constructor(dbPathOrDb: string | Database = SqliteOAuthClientDb.getDefaultDbPath(), encryptionKey?: string) {
    encryptionKey = encryptionKey || process.env[DEFAULT_ENCRYPTION_KEY_ENV_VAR];
    if (!encryptionKey) {
      throw new Error(`No encryptionKey provided and ${DEFAULT_ENCRYPTION_KEY_ENV_VAR} environment variable is not set`);
    }
    this.encryptionKey = encryptionKey;

    this.db = typeof dbPathOrDb === 'string' ? new Database(dbPathOrDb) : dbPathOrDb;
    this.run = promisify(this.db.run.bind(this.db));
    this.get = promisify(this.db.get.bind(this.db));
    this.all = promisify(this.db.all.bind(this.db));
    this.dbClose = promisify(this.db.close.bind(this.db));
  }

  ensureInitialized = async (): Promise<void> => {
    if (this.initialized) return;

    // Create tables
    await this.run(`
      CREATE TABLE IF NOT EXISTS oauth_client_credentials (
        resource_server_url TEXT PRIMARY KEY,
        encrypted_client_id TEXT NOT NULL,
        encrypted_client_secret TEXT NOT NULL,
        redirect_uri TEXT NOT NULL
      )
    `, []);

    await this.run(`
      CREATE TABLE IF NOT EXISTS oauth_pkce_values (
        state TEXT PRIMARY KEY,
        encrypted_code_verifier TEXT NOT NULL,
        encrypted_code_challenge TEXT NOT NULL,
        resource_server_url TEXT NOT NULL
      )
    `, []);

    await this.run(`
      CREATE TABLE IF NOT EXISTS oauth_access_tokens (
        resource_server_url TEXT PRIMARY KEY,
        encrypted_access_token TEXT NOT NULL,
        encrypted_refresh_token TEXT,
        expires_at TEXT
      )
    `, []);

    this.initialized = true;
  }

  getClientCredentials = async (resourceServerUrl: string): Promise<ClientCredentials | null> => {
    await this.ensureInitialized();
    const row = await this.get(
      'SELECT encrypted_client_id, encrypted_client_secret, redirect_uri FROM oauth_client_credentials WHERE resource_server_url = ?',
      [resourceServerUrl]
    );
    return row ? {
      clientId: decrypt(row.encrypted_client_id, this.encryptionKey),
      clientSecret: decrypt(row.encrypted_client_secret, this.encryptionKey),
      redirectUri: row.redirect_uri
    } : null;
  }

  saveClientCredentials = async (
    resourceServerUrl: string,
    credentials: ClientCredentials
  ): Promise<void> => {
    await this.ensureInitialized();
    await this.run(
      'INSERT OR REPLACE INTO oauth_client_credentials (resource_server_url, encrypted_client_id, encrypted_client_secret, redirect_uri) VALUES (?, ?, ?, ?)',
      [
        resourceServerUrl,
        encrypt(credentials.clientId, this.encryptionKey),
        encrypt(credentials.clientSecret, this.encryptionKey),
        credentials.redirectUri
      ]
    );
  }

  getPKCEValues = async (state: string): Promise<PKCEValues | null> => {
    await this.ensureInitialized();
    const row = await this.get(
      'SELECT encrypted_code_verifier, encrypted_code_challenge, resource_server_url FROM oauth_pkce_values WHERE state = ?',
      [state]
    );
    return row ? {
      codeVerifier: decrypt(row.encrypted_code_verifier, this.encryptionKey),
      codeChallenge: decrypt(row.encrypted_code_challenge, this.encryptionKey),
      resourceServerUrl: row.resource_server_url
    } : null;
  }

  savePKCEValues = async (
    state: string,
    values: PKCEValues
  ): Promise<void> => {
    await this.ensureInitialized();
    await this.run(
      'INSERT INTO oauth_pkce_values (state, encrypted_code_verifier, encrypted_code_challenge, resource_server_url) VALUES (?, ?, ?, ?)',
      [
        state,
        encrypt(values.codeVerifier, this.encryptionKey),
        encrypt(values.codeChallenge, this.encryptionKey),
        values.resourceServerUrl
      ]
    );
  }

  getAccessToken = async (resourceServerUrl: string): Promise<{
    accessToken: string,
    refreshToken?: string,
    expiresAt?: Date
  } | null> => {
    await this.ensureInitialized();
    const row = await this.get(
      'SELECT encrypted_access_token, encrypted_refresh_token, expires_at FROM oauth_access_tokens WHERE resource_server_url = ?',
      [resourceServerUrl]
    );
    if (!row) return null;

    return {
      accessToken: decrypt(row.encrypted_access_token, this.encryptionKey),
      refreshToken: row.encrypted_refresh_token ? decrypt(row.encrypted_refresh_token, this.encryptionKey) : undefined,
      expiresAt: row.expires_at ? new Date(row.expires_at) : undefined
    };
  }

  saveAccessToken = async (
    resourceServerUrl: string,
    token: {
      accessToken: string,
      refreshToken?: string,
      expiresAt?: Date
    }
  ): Promise<void> => {
    await this.ensureInitialized();
    await this.run(
      'INSERT OR REPLACE INTO oauth_access_tokens (resource_server_url, encrypted_access_token, encrypted_refresh_token, expires_at) VALUES (?, ?, ?, ?)',
      [
        resourceServerUrl,
        encrypt(token.accessToken, this.encryptionKey),
        token.refreshToken ? encrypt(token.refreshToken, this.encryptionKey) : null,
        token.expiresAt?.toISOString()
      ]
    );
  }

  close = async (): Promise<void> => {
    try {
      await this.dbClose();
    } catch (error) {
      // If database is already closed, just log and continue
      if (error && typeof error === 'object' && 'code' in error && error.code === 'SQLITE_MISUSE') {
        console.log('Database already closed');
      } else {
        throw error;
      }
    }
  }
}