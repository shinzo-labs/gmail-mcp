import { LOG_PATH } from "./config.js"
import fs from "fs"

type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error'

type Log = {
  timestamp: string
  level: LogLevel
  message: string
  data?: any
}

export const logger = (level: LogLevel, message: string, data?: any) => {
  const log: Log = { timestamp: new Date().toISOString(), level, message }
  if (data) log.data = data

  try {
    fs.appendFileSync(LOG_PATH, JSON.stringify(log) + '\n')
  } catch (error: any) {
    console.error('Error writing to log file:', { error: error.message })
  }
}
