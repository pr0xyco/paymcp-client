import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { DEFAULT_ENCRYPTION_KEY_ENV_VAR, encrypt, decrypt } from '@longrun/crypto-utils/src/index';
import type { ClientCredentials, PKCEValues, AccessToken, OAuthClientDb } from './types';

export class SqliteOAuthClientDb implements OAuthClientDb {
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

  constructor(dbPathOrDb: string | Database.Database = SqliteOAuthClientDb.getDefaultDbPath(), encryptionKey?: string) {
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
        resource_server_url TEXT PRIMARY KEY,
        encrypted_client_id TEXT NOT NULL,
        encrypted_client_secret TEXT NOT NULL,
        redirect_uri TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS oauth_pkce_values (
        state TEXT PRIMARY KEY,
        encrypted_code_verifier TEXT NOT NULL,
        encrypted_code_challenge TEXT NOT NULL,
        resource_server_url TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS oauth_access_tokens (
        resource_server_url TEXT PRIMARY KEY,
        encrypted_access_token TEXT NOT NULL,
        encrypted_refresh_token TEXT,
        expires_at TEXT
      );
    `);

    this.initialized = true;
  }

  getClientCredentials = async (resourceServerUrl: string): Promise<ClientCredentials | null> => {
    await this.ensureInitialized();
    const row = this.db.prepare(
      'SELECT encrypted_client_id, encrypted_client_secret, redirect_uri FROM oauth_client_credentials WHERE resource_server_url = ?'
    ).get(resourceServerUrl) as { encrypted_client_id: string; encrypted_client_secret: string; redirect_uri: string } | undefined;

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
    this.db.prepare(
      'INSERT OR REPLACE INTO oauth_client_credentials (resource_server_url, encrypted_client_id, encrypted_client_secret, redirect_uri) VALUES (?, ?, ?, ?)'
    ).run(
      resourceServerUrl,
      encrypt(credentials.clientId, this.encryptionKey),
      encrypt(credentials.clientSecret, this.encryptionKey),
      credentials.redirectUri
    );
  }

  getPKCEValues = async (state: string): Promise<PKCEValues | null> => {
    await this.ensureInitialized();
    const row = this.db.prepare(
      'SELECT encrypted_code_verifier, encrypted_code_challenge, resource_server_url FROM oauth_pkce_values WHERE state = ?'
    ).get(state) as { encrypted_code_verifier: string; encrypted_code_challenge: string; resource_server_url: string } | undefined;

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
    this.db.prepare(
      'INSERT INTO oauth_pkce_values (state, encrypted_code_verifier, encrypted_code_challenge, resource_server_url) VALUES (?, ?, ?, ?)'
    ).run(
      state,
      encrypt(values.codeVerifier, this.encryptionKey),
      encrypt(values.codeChallenge, this.encryptionKey),
      values.resourceServerUrl
    );
  }

  getAccessToken = async (resourceServerUrl: string): Promise<AccessToken | null> => {
    await this.ensureInitialized();
    const row = this.db.prepare(
      'SELECT encrypted_access_token, encrypted_refresh_token, expires_at FROM oauth_access_tokens WHERE resource_server_url = ?'
    ).get(resourceServerUrl) as { encrypted_access_token: string; encrypted_refresh_token: string | null; expires_at: string | null } | undefined;

    if (!row) return null;

    return {
      accessToken: decrypt(row.encrypted_access_token, this.encryptionKey),
      refreshToken: row.encrypted_refresh_token ? decrypt(row.encrypted_refresh_token, this.encryptionKey) : undefined,
      expiresAt: row.expires_at ? parseInt(row.expires_at) : undefined
    };
  }

  saveAccessToken = async (
    resourceServerUrl: string,
    token: AccessToken
  ): Promise<void> => {
    await this.ensureInitialized();
    this.db.prepare(
      'INSERT OR REPLACE INTO oauth_access_tokens (resource_server_url, encrypted_access_token, encrypted_refresh_token, expires_at) VALUES (?, ?, ?, ?)'
    ).run(
      resourceServerUrl,
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