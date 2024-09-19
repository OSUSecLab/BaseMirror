package analyze;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * This class contains constant values and configurations used throughout the analysis.
 * It includes directory paths, project names, API names, and function lists.
 */
public class Constants {

    // Directory where output files will be stored
    public static String DIRECTORY_NAME;

    static {
        // Set DIRECTORY_NAME to the current working directory
        DIRECTORY_NAME = System.getProperty("user.dir");
    }

    // Name of the Ghidra project
    public static String PROJECT_NAME = "RIL_Analyzer";

    // Directory for output files
    public static String OUTPUT_DIR;

    static {
        // Set OUTPUT_DIR to a subdirectory named "output" within DIRECTORY_NAME
        OUTPUT_DIR = DIRECTORY_NAME + File.separator + "output";
    }

    // Directory where RIL binaries are stored
    public static String RIL_BINARIES;

    static {
        // Set RIL_BINARIES to a subdirectory named "ril_binaries" within DIRECTORY_NAME
        RIL_BINARIES = DIRECTORY_NAME + File.separator + "ril_binaries";
    }

    // API names for Qualcomm
    public static String QC_SEND_MSG_ASYNC = "qcril_qmi_client_send_msg_async";
    public static String QC_SEND_MSG_SYNC = "qcril_qmi_client_send_msg_sync";
    public static String QC_SEND_UNSOL = "qcril_send_unsol_response";
    public static String QC_HOOK_UNSOL_RESPONSE = "qcril_hook_unsol_response";
    public static String QC_IMS_SOCKET_SEND = "qcril_qmi_ims_socket_send";

    // API names for Samsung
    public static String SS_SEND_MSG = "IpcModem::sendMessage";
    public static String SS_SUBJECT_TO_FORWARD = "IpcHijacker::SubjectToForward";

    // Basic C I/O Functions
    public static String C_WRITE = "write";
    public static String C_READ = "read";
    public static String C_SEND_TO = "sendto"; // socket communication
    public static String C_IOCTL = "ioctl";
    public static String C_FWRITE = "fwrite"; // file I/O
    public static String C_WRITE_CHK = "__write_chk"; // check function
    public static String C_READ_CHK = "__read_chk"; // check function

    // List of functions related to opening files or pipes
    public static ArrayList<String> OpenFuncs = new ArrayList<>(Arrays.asList("open", "__open_2", "fopen", "pipe"));

    // List of operations for handling call and branch instructions
    public static ArrayList<String> OpenTerOPs = new ArrayList<>(Arrays.asList("CALL", "CBRANCH"));

    // List of functions related to formatting strings
    public static ArrayList<String> FormatFuncs = new ArrayList<>(Arrays.asList("__vsnprintf_chk"));

    // Blacklist of functions to be ignored during analysis
    public static ArrayList<String> funcBlackList = new ArrayList<>(Arrays.asList(
        "OnRequestComplete",
        "OnUnsolicitedResponse",
        "AsyncReceiver::Notify",
        "Init",
        "__android_log_buf_print",
        "Nv::NvLog",
        "operator.delete[]",
        "operator.new[]"
    ));
}
