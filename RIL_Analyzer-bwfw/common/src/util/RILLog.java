package util;

import analyze.Config;
import analyze.Constants;
import analyze.Global;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * RILLog provides logging functionality for different levels of messages.
 */
public class RILLog {

    /**
     * Initializes the logging system by setting up a PrintStream to a log file.
     * The log file is named with the specified fileName and the current date and time.
     *
     * @param fileName The base name for the log file.
     */
    public static void initLog(String fileName) {

        // Get current date and time
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");
        String dateStr = now.format(formatter);

        try {
            // Create the directory if it does not exist
            File dir = new File(Constants.OUTPUT_DIR + File.separator + Global.rilName + "_LOG");
            if (!dir.exists())
                dir.mkdirs();
                
            // Create a PrintStream to write logs to the file
            PrintStream fs = new PrintStream(dir.toString() + File.separator + fileName + "." + dateStr);
            System.setOut(fs); // Redirect standard output to the log file
        } catch (IOException e) {
            e.printStackTrace(); // Print stack trace if an error occurs
            return;
        }
    }

    /**
     * Logs a debug message if debugging is enabled.
     *
     * @param str The message to log.
     */
    public static void debugLog(String str) {
        if (Config.DEBUG_LOG) {
            System.out.println("[DEBUG] " + str);
        }
    }

    /**
     * Logs an informational message if info logging is enabled.
     *
     * @param str The message to log.
     */
    public static void infoLog(String str) {
        if (Config.INFO_LOG) {
            System.out.println("[INFO] " + str);
        }
    }

    /**
     * Logs an error message if error logging is enabled.
     *
     * @param str The message to log.
     */
    public static void errorLog(String str) {
        if (Config.ERROR_LOG) {
            System.out.println("[ERROR] " + str);
        }
    }
}
