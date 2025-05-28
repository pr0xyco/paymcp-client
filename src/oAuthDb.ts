import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { DEFAULT_ENCRYPTION_KEY_ENV_VAR, encrypt, decrypt } from './crypto-utils.js';
import type { ClientCredentials, PKCEValues, AccessToken, OAuthDb } from './types';

export class SqliteOAuthDb implements OAuthDb {
  private db: Database.Database;
  private initialized = false;
  private encryptionKey: string;

  static getDefaultDbPath(): string {
    const dbDir = path.join(process.cwd(), 'db');
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }
    return path.join(dbDir, 'oauthClient.db');
  }

  constructor(dbPathOrDb: string | Database.Database = SqliteOAuthDb.getDefaultDbPath(), encryptionKey?: string) {
    encryptionKey = encryptionKey || process.env[DEFAULT_ENCRYPTION_KEY_ENV_VAR];
    if (!encryptionKey) {
      throw new Error(`No encryptionKey provided and ${DEFAULT_ENCRYPTION_KEY_ENV_VAR} environment variable is not set`);
    }
    this.encryptionKey = encryptionKey;

    this.db = typeof dbPathOrDb === 'string' ? new Database(dbPathOrDb) : dbPathOrDb;
  }

  ensureInitialized = async (): Promise<void> => {
    if (this.initialized) return;

    // Create tables
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS oauth_client_credentials (
        resource_url TEXT PRIMARY KEY,
        encrypted_client_id TEXT NOT NULL,
        encrypted_client_secret TEXT NOT NULL,
        redirect_uri TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS oauth_pkce_values (
        user_id TEXT NOT NULL,
        state TEXT NOT NULL,
        encrypted_code_verifier TEXT NOT NULL,
        encrypted_code_challenge TEXT NOT NULL,
        resource_url TEXT NOT NULL,
        url TEXT NOT NULL,
        PRIMARY KEY (user_id, state)
      );

      CREATE TABLE IF NOT EXISTS oauth_access_tokens (
        user_id TEXT NOT NULL,
        url TEXT NOT NULL,
        resource_url TEXT NOT NULL,
        encrypted_access_token TEXT NOT NULL,
        encrypted_refresh_token TEXT,
        expires_at TEXT,
        PRIMARY KEY (user_id, url)
      );
    `);

    this.initialized = true;
  }

  getClientCredentials = async (resourceUrl: string): Promise<ClientCredentials | null> => {
    await this.ensureInitialized();
    const row = this.db.prepare(
      'SELECT encrypted_client_id, encrypted_client_secret, redirect_uri FROM oauth_client_credentials WHERE resource_url = ?'
    ).get(resourceUrl) as { encrypted_client_id: string; encrypted_client_secret: string; redirect_uri: string } | undefined;

    return row ? {
      clientId: decrypt(row.encrypted_client_id, this.encryptionKey),
      clientSecret: decrypt(row.encrypted_client_secret, this.encryptionKey),
      redirectUri: row.redirect_uri
    } : null;
  }

  saveClientCredentials = async (
    resourceUrl: string,
    credentials: ClientCredentials
  ): Promise<void> => {
    await this.ensureInitialized();
    this.db.prepare(
      'INSERT OR REPLACE INTO oauth_client_credentials (resource_url, encrypted_client_id, encrypted_client_secret, redirect_uri) VALUES (?, ?, ?, ?)'
    ).run(
      resourceUrl,
      encrypt(credentials.clientId, this.encryptionKey),
      encrypt(credentials.clientSecret, this.encryptionKey),
      credentials.redirectUri
    );
  }

  getPKCEValues = async (userId: string, state: string): Promise<PKCEValues | null> => {
    await this.ensureInitialized();
    const row = this.db.prepare(
      'SELECT encrypted_code_verifier, encrypted_code_challenge, resource_url, url FROM oauth_pkce_values WHERE user_id = ? AND state = ?'
    ).get(userId, state) as { encrypted_code_verifier: string; encrypted_code_challenge: string; resource_url: string; url: string } | undefined;

    return row ? {
      codeVerifier: decrypt(row.encrypted_code_verifier, this.encryptionKey),
      codeChallenge: decrypt(row.encrypted_code_challenge, this.encryptionKey),
      resourceUrl: row.resource_url,
      url: row.url
    } : null;
  }

  savePKCEValues = async (
    userId: string,
    state: string,
    values: PKCEValues
  ): Promise<void> => {
    await this.ensureInitialized();
    this.db.prepare(
      'INSERT INTO oauth_pkce_values (user_id, state, encrypted_code_verifier, encrypted_code_challenge, resource_url, url) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(
      userId,
      state,
      encrypt(values.codeVerifier, this.encryptionKey),
      encrypt(values.codeChallenge, this.encryptionKey),
      values.resourceUrl,
      values.url
    );
  }

  getAccessToken = async (userId: string, url: string): Promise<AccessToken | null> => {
    await this.ensureInitialized();
    const row = this.db.prepare(
      'SELECT resource_url, encrypted_access_token, encrypted_refresh_token, expires_at FROM oauth_access_tokens WHERE user_id = ? AND url = ?'
    ).get(userId, url) as { resource_url: string; encrypted_access_token: string; encrypted_refresh_token: string | null; expires_at: string | null } | undefined;

    if (!row) return null;

    return {
      accessToken: decrypt(row.encrypted_access_token, this.encryptionKey),
      refreshToken: row.encrypted_refresh_token ? decrypt(row.encrypted_refresh_token, this.encryptionKey) : undefined,
      expiresAt: row.expires_at ? parseInt(row.expires_at) : undefined,
      resourceUrl: row.resource_url
    };
  }

  saveAccessToken = async (
    userId: string,
    url: string,
    token: AccessToken
  ): Promise<void> => {
    await this.ensureInitialized();
    this.db.prepare(
      'INSERT OR REPLACE INTO oauth_access_tokens (user_id, url, resource_url, encrypted_access_token, encrypted_refresh_token, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(
      userId,
      url,
      token.resourceUrl,
      encrypt(token.accessToken, this.encryptionKey),
      token.refreshToken ? encrypt(token.refreshToken, this.encryptionKey) : null,
      token.expiresAt?.toString()
    );
  }

  close = async (): Promise<void> => {
    try {
      this.db.close();
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