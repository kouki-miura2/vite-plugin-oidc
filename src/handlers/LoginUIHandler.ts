/**
 * Login UI Handler for OIDC Login Page
 * Handles login page display and form submission
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import type {
  LoginUIHandler as ILoginUIHandler,
  Request,
  Response
} from '../types/handlers.js';
import type {
  InMemoryStore,
  Session
} from '../types/storage.js';
import type {
  UserAccount,
  OIDCPluginConfig
} from '../types/config.js';

// Get current directory for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load HTML templates at build time
const loginHTML = fs.readFileSync(
  path.join(__dirname, '../assets/templates/login.html'),
  'utf-8'
);

export class LoginUIHandler implements ILoginUIHandler {
  private store: InMemoryStore;
  private config: OIDCPluginConfig;
  private users: UserAccount[];

  constructor(
    store: InMemoryStore,
    config: OIDCPluginConfig,
    users: UserAccount[]
  ) {
    this.store = store;
    this.config = config;
    this.users = users;
  }

  async handleLoginPage(req: Request, res: Response): Promise<void> {
    try {
      // Parse query parameters to get return_to URL and any error messages
      const url = new URL(req.url || '', 'http://localhost');
      const returnTo = url.searchParams.get('return_to') || '';
      const error = url.searchParams.get('error') || undefined;

      // Debug logging
      if (this.config.development?.enableLogging) {
        console.log('[LoginUI] Page request', {
          url: req.url,
          returnTo,
          error,
          userAgent: req.headers['user-agent']
        });
      }

      // Generate login HTML
      const loginHtml = this.generateLoginHTML(this.users, error, returnTo);

      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(loginHtml);

    } catch (error) {
      console.error('Login page handler error:', error);
      res.statusCode = 500;
      res.setHeader('Content-Type', 'text/plain');
      res.end('Internal Server Error');
    }
  }

  async handleLoginSubmit(req: Request, res: Response): Promise<void> {
    try {
      console.log('Login submit - Request method:', req.method);
      console.log('Login submit - Request URL:', req.url);
      console.log('Login submit - Request headers:', req.headers);
      console.log('Login submit - Request body type:', typeof req.body);
      console.log('Login submit - Request body:', req.body);

      // Parse form data from request body
      const formData = await this.parseFormData(req);
      console.log('Login submit - Parsed form data:', formData);
      const { username, password, return_to } = formData;

      // Validate credentials
      const user = this.validateCredentials(username, password);

      if (!user) {
        // Authentication failed, redirect back to login with error
        const basePath = this.config.basePath || '/oidc';
        let errorUrl = `${basePath}/login?error=${encodeURIComponent('Invalid username or password')}`;
        if (return_to) {
          errorUrl += `&return_to=${encodeURIComponent(return_to)}`;
        }

        res.statusCode = 302;
        res.setHeader('Location', errorUrl);
        res.end();
        return;
      }

      // Authentication successful, create session
      const sessionId = this.generateSessionId();
      const sessionExpiration = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

      const session: Session = {
        sessionId,
        userId: user.id,
        createdAt: Date.now(),
        expiresAt: sessionExpiration
      };

      this.store.storeSession(session);
      console.log('Login - Session created:', { sessionId, userId: user.id, expiresAt: sessionExpiration });

      // Set session cookie
      // Use root path to ensure cookie is accessible across all paths
      const cookieValue = `oidc_session=${sessionId}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`;
      console.log('Login - Setting cookie:', cookieValue);
      res.setHeader('Set-Cookie', cookieValue);

      // Redirect back to original authorization request
      if (return_to) {
        // Ensure the return_to URL includes the basePath
        const basePath = this.config.basePath || '/oidc';
        let redirectUrl = return_to;

        // If return_to is a relative path starting with /authorize, prepend basePath
        if (return_to.startsWith('/authorize')) {
          redirectUrl = basePath + return_to;
        }

        console.log('Login - Redirecting to:', redirectUrl);
        res.statusCode = 302;
        res.setHeader('Location', redirectUrl);
        res.end();
      } else {
        // No return URL, show simple success message
        res.statusCode = 200;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.end('Login successful');
      }

    } catch (error) {
      console.error('Login submit handler error:', error);
      res.statusCode = 500;
      res.setHeader('Content-Type', 'text/plain');
      res.end('Internal Server Error');
    }
  }

  generateLoginHTML(users: UserAccount[], error?: string, returnTo?: string): string {
    const basePath = this.config.basePath || '/oidc';

    // Debug mode - log when login page is generated
    if (this.config.development?.enableLogging) {
      console.log('[LoginUI] Generating login page', { error, returnTo, userCount: users.length });
    }

    const errorMessage = error ?
      `<div class="error">
        ${this.escapeHtml(error)}
      </div>` : '';

    // Replace template variables (using global replace)
    return loginHTML
      .replace(/\{\{title\}\}/g, this.config.loginUI?.title || 'OIDC Login')
      .replace(/\{\{errorMessage\}\}/g, errorMessage)
      .replace(/\{\{basePath\}\}/g, basePath)
      .replace(/\{\{returnTo\}\}/g, this.escapeHtml(returnTo || ''));
  }

  private validateCredentials(username: string, password: string): UserAccount | null {
    return this.users.find(user =>
      user.username === username && user.password === password
    ) || null;
  }

  private generateSessionId(): string {
    // Generate a secure random session ID
    const timestamp = Date.now().toString();
    const randomBytes = Math.random().toString(36).substring(2);
    const sessionData = `session:${timestamp}:${randomBytes}`;

    return Buffer.from(sessionData).toString('base64url');
  }

  private async parseFormData(req: Request): Promise<Record<string, string>> {
    return new Promise((resolve, reject) => {
      let body = '';

      console.log('parseFormData - req.body exists:', !!req.body);
      console.log('parseFormData - req.body type:', typeof req.body);
      console.log('parseFormData - req.body value:', req.body);

      // Handle different ways the body might be provided
      if (req.body) {
        if (typeof req.body === 'string') {
          body = req.body;
          console.log('parseFormData - Using string body:', body);
        } else if (req.body instanceof Buffer) {
          body = req.body.toString();
          console.log('parseFormData - Using buffer body:', body);
        } else if (typeof req.body === 'object') {
          // Assume it's already parsed
          console.log('parseFormData - Using parsed object body:', req.body);
          resolve(req.body);
          return;
        }
      }

      if (body) {
        try {
          // Parse URL-encoded form data
          const formData: Record<string, string> = {};
          const pairs = body.split('&');

          for (const pair of pairs) {
            const [key, value] = pair.split('=');
            if (key && value !== undefined) {
              formData[decodeURIComponent(key)] = decodeURIComponent(value.replace(/\+/g, ' '));
            }
          }

          console.log('parseFormData - Parsed form data:', formData);
          resolve(formData);
        } catch (error) {
          console.error('parseFormData - Parse error:', error);
          reject(error);
        }
      } else {
        // Try to read from request stream if no body is available
        console.log('parseFormData - No body found, trying to read from stream');

        if (req.on) {
          const chunks: Buffer[] = [];

          req.on('data', (chunk: Buffer) => {
            console.log('parseFormData - Received chunk:', chunk.toString());
            chunks.push(chunk);
          });

          req.on('end', () => {
            try {
              const bodyString = Buffer.concat(chunks).toString();
              console.log('parseFormData - Stream body:', bodyString);

              if (!bodyString) {
                reject(new Error('No form data received'));
                return;
              }

              const formData: Record<string, string> = {};
              const pairs = bodyString.split('&');

              for (const pair of pairs) {
                const [key, value] = pair.split('=');
                if (key && value !== undefined) {
                  formData[decodeURIComponent(key)] = decodeURIComponent(value.replace(/\+/g, ' '));
                }
              }

              console.log('parseFormData - Stream parsed form data:', formData);
              resolve(formData);
            } catch (error) {
              console.error('parseFormData - Stream parse error:', error);
              reject(error);
            }
          });

          req.on('error', (error: Error) => {
            console.error('parseFormData - Stream error:', error);
            reject(error);
          });
        } else {
          reject(new Error('Request stream not available'));
        }
      }
    });
  }

  private escapeHtml(text: string): string {
    const div = { innerHTML: '' } as any;
    div.textContent = text;
    return div.innerHTML || text.replace(/[&<>"']/g, (match: string) => {
      const escapeMap: Record<string, string> = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      };
      return escapeMap[match];
    });
  }




}