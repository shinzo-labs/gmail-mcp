import { LOG_PATH } from "./config.js";
import fs from "fs";
export const logger = (level, message, data) => {
    const log = { timestamp: new Date().toISOString(), level, message };
    if (data)
        log.data = data;
    try {
        fs.appendFileSync(LOG_PATH, JSON.stringify(log) + '\n');
    }
    catch (error) {
        console.error('Error writing to log file:', { error: error.message });
    }
};
