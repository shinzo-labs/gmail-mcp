"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateCredentials = exports.launchAuthServer = exports.createOAuth2Client = void 0;
const config_1 = require("./config");
const logger_1 = require("./logger");
const google_auth_library_1 = require("google-auth-library");
const fs_1 = __importDefault(require("fs"));
const http_1 = __importDefault(require("http"));
const open_1 = __importDefault(require("open"));
const AUTH_SCOPES = [
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.compose',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.settings.basic',
    'https://www.googleapis.com/auth/gmail.settings.sharing'
];
const createOAuth2Client = () => {
    try {
        (0, logger_1.logger)('info', 'Starting OAuth2Client creation');
        if (!fs_1.default.existsSync(config_1.GMAIL_OAUTH_PATH)) {
            (0, logger_1.logger)('error', `OAuth2 keys file not found at ${config_1.GMAIL_OAUTH_PATH}`);
            process.exit(1);
        }
        let parsedKeys;
        const keysContent = fs_1.default.readFileSync(config_1.GMAIL_OAUTH_PATH, 'utf8');
        parsedKeys = JSON.parse(keysContent);
        if (!parsedKeys?.installed.client_id || !parsedKeys.installed.client_secret) {
            (0, logger_1.logger)('error', 'Invalid OAuth keys format', parsedKeys);
            process.exit(1);
        }
        const keys = parsedKeys;
        (0, logger_1.logger)('info', 'Creating OAuth2Client with credentials');
        const oauth2Client = new google_auth_library_1.OAuth2Client({
            clientId: keys.installed.client_id,
            clientSecret: keys.installed.client_secret,
            redirectUri: 'http://localhost:3000/oauth2callback'
        });
        if (fs_1.default.existsSync(config_1.GMAIL_CREDENTIALS_PATH)) {
            (0, logger_1.logger)('info', `Found existing credentials file at ${config_1.GMAIL_CREDENTIALS_PATH}`);
            const credentials = JSON.parse(fs_1.default.readFileSync(config_1.GMAIL_CREDENTIALS_PATH, 'utf8'));
            oauth2Client.setCredentials(credentials);
            (0, logger_1.logger)('info', 'Successfully loaded existing credentials');
        }
        else {
            (0, logger_1.logger)('info', `No existing credentials file found at ${config_1.GMAIL_CREDENTIALS_PATH}`);
        }
        return oauth2Client;
    }
    catch (error) {
        (0, logger_1.logger)('error', 'Failed to create OAuth2Client', { error: error.message });
        process.exit(1);
    }
};
exports.createOAuth2Client = createOAuth2Client;
const launchAuthServer = async (oauth2Client) => new Promise((resolve, reject) => {
    const server = http_1.default.createServer();
    server.listen(3000);
    const authUrl = oauth2Client.generateAuthUrl({ access_type: 'offline', scope: AUTH_SCOPES });
    (0, logger_1.logger)('info', `Please visit this URL to authenticate: ${authUrl}`);
    (0, open_1.default)(authUrl);
    server.on('request', async (req, res) => {
        if (!req.url?.startsWith('/oauth2callback'))
            return;
        const url = new URL(req.url, 'http://localhost:3000');
        const code = url.searchParams.get('code');
        if (!code) {
            res.writeHead(400);
            res.end('No code provided');
            reject(new Error('No code provided'));
            return;
        }
        try {
            const { tokens } = await oauth2Client.getToken(code);
            oauth2Client.setCredentials(tokens);
            fs_1.default.writeFileSync(config_1.GMAIL_CREDENTIALS_PATH, JSON.stringify(tokens, null, 2));
            res.writeHead(200);
            res.end('Authentication successful! You can close this window.');
            server.close();
            resolve(void 0);
        }
        catch (error) {
            res.writeHead(500);
            res.end('Authentication failed');
            reject(error);
        }
    });
});
exports.launchAuthServer = launchAuthServer;
const validateCredentials = async (oauth2Client) => {
    try {
        const { credentials } = oauth2Client;
        if (!credentials) {
            (0, logger_1.logger)('info', 'No credentials found, please re-authenticate');
            return false;
        }
        const currentTime = Date.now();
        const expiryDate = credentials.expiry_date;
        const needsRefresh = !expiryDate || expiryDate <= currentTime;
        if (!needsRefresh) {
            (0, logger_1.logger)('info', 'Credentials are valid');
            return true;
        }
        if (!credentials.refresh_token) {
            (0, logger_1.logger)('info', 'No refresh token found, please re-authenticate');
            return false;
        }
        const timeUntilExpiry = expiryDate ? (expiryDate - currentTime) : 0;
        (0, logger_1.logger)('info', `Access token is ${timeUntilExpiry > 0 ? 'expiring in ' + timeUntilExpiry + ' seconds' : 'expired'}, refreshing token`);
        const { credentials: tokens } = await oauth2Client.refreshAccessToken();
        oauth2Client.setCredentials(tokens);
        fs_1.default.writeFileSync(config_1.GMAIL_CREDENTIALS_PATH, JSON.stringify(tokens, null, 2));
        (0, logger_1.logger)('info', 'Successfully refreshed and saved new credentials');
        return true;
    }
    catch (error) {
        (0, logger_1.logger)('error', 'Error validating credentials', { error: error.message });
        return false;
    }
};
exports.validateCredentials = validateCredentials;
