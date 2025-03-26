"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.GMAIL_CREDENTIALS_PATH = exports.GMAIL_OAUTH_PATH = exports.LOG_PATH = exports.CONFIG_DIR = void 0;
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
exports.CONFIG_DIR = path_1.default.join(os_1.default.homedir(), '.gmail-mcp');
exports.LOG_PATH = process.env.LOG_PATH || path_1.default.join(exports.CONFIG_DIR, 'gmail-mcp.log');
exports.GMAIL_OAUTH_PATH = process.env.GMAIL_OAUTH_PATH || path_1.default.join(exports.CONFIG_DIR, 'gcp-oauth.keys.json');
exports.GMAIL_CREDENTIALS_PATH = process.env.GMAIL_CREDENTIALS_PATH || path_1.default.join(exports.CONFIG_DIR, 'credentials.json');
