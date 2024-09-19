package analyze;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;

public class Constants {

    // Base directory for the analyzer.
    public static String DIRECTORY_NAME;
    static {
        // Set the directory name to the current working directory.
        DIRECTORY_NAME = System.getProperty("user.dir");
    }

    // Project name for the analyzer.
    public static String PROJECT_NAME = "RIL_Analyzer";

    // Output directory for saving analysis results.
    public static String OUTPUT_DIR;
    static {
        // Set the output directory path based on the base directory.
        OUTPUT_DIR = DIRECTORY_NAME + File.separator + "output";
    }

    // Directory containing RIL binaries.
    public static String RIL_BINARIES;
    static {
        // Set the path for RIL binaries based on the base directory.
        RIL_BINARIES = DIRECTORY_NAME + File.separator + "ril_binaries";
    }

    // API function names for QualComm.
    public static String QC_SEND_MSG_ASYNC = "qcril_qmi_client_send_msg_async";
    public static String QC_SEND_MSG_SYNC = "qcril_qmi_client_send_msg_sync";
    public static String QC_SEND_UNSOL = "qcril_send_unsol_response";
    public static String QC_HOOK_UNSOL_RESPONSE = "qcril_hook_unsol_response";
    public static String QC_IMS_SOCKET_SEND = "qcril_qmi_ims_socket_send";

    // API function names for Samsung.
    public static String SS_SEND_MSG = "IpcModem::sendMessage";
    public static String SS_SUBJECT_TO_FORWARD = "IpcHijacker::SubjectToForward";

    // Basic C I/O function names.
    public static String C_WRITE = "write"; // Write to file descriptor.
    public static String C_READ = "read"; // Read from file descriptor.
    public static String C_SEND_TO = "sendto"; // Send data to a socket.
    public static String C_IOCTL = "ioctl"; // Control device.
    public static String C_FWRITE = "fwrite"; // Write to file stream.
    public static String C_WRITE_CHUNK = "__write_chk"; // Write chunk with checking.

    // List of functions related to opening files or resources.
    public static ArrayList<String> OpenFuncs = new ArrayList<String>(Arrays.asList("open", "__open_2", "fopen", "pipe"));

    // List of operations that indicate opening or termination of operations.
    public static ArrayList<String> OpenTerOPs = new ArrayList<String>(Arrays.asList("CALL", "CBRANCH"));

    // List of functions related to formatting.
    public static ArrayList<String> FormatFuncs = new ArrayList<String>(Arrays.asList("__vsnprintf_chk"));

    // Blacklist of function names to be excluded from analysis.
    public static ArrayList<String> funcBlackList = new ArrayList<>(Arrays.asList("OnRequestComplete",
            "OnUnsolicitedResponse", "AsyncReceiver::Notify", "Init"));
}
