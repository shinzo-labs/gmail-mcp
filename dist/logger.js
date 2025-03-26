"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
const config_1 = require("./config");
const fs_1 = __importDefault(require("fs"));
const logger = (level, message, data) => {
    const log = { timestamp: new Date().toISOString(), level, message };
    if (data)
        log.data = data;
    try {
        fs_1.default.appendFileSync(config_1.LOG_PATH, JSON.stringify(log) + '\n');
    }
    catch (error) {
        console.error('Error writing to log file:', { error: error.message });
    }
};
exports.logger = logger;
