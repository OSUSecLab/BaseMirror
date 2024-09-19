package analyze;

public class Config {

    // Timeout for disassembling, in milliseconds.
    public static long DISASSEMBLE_TIMEOUT = 3000;

    // Timeout for decompiling, in seconds.
    public final static int DECOMPILE_TIMEOUT = 300; // s

    // Maximum recursion depth allowed during analysis.
    public final static int MAX_RESURSION = 5;

    // Maximum number of function jumps allowed during analysis.
    public final static int MAX_FUNCTION_JUMP = 20;

    // Maximum depth of p-code evaluation during analysis.
    public final static int MAX_PCODE_EVAL_DEPTH = 20;

    // Mode for decompilation, options are: "decompile"|"normalize"|"register"|"firstpass"|"paramid".
    public final static String DECOMPILE_MODE = "decompile";

    // Flag to enable or disable debug logging.
    public final static boolean DEBUG_LOG = true;

    // Flag to enable or disable informational logging.
    public final static boolean INFO_LOG = true;

    // Flag to enable or disable error logging.
    public final static boolean ERROR_LOG = true;

    // Flag to enable or disable caching of function compilation results.
    public final static boolean DECOMPILER_CACHE = true; // Enable to save function compilation results as cache.

    // Flag to determine whether to solve all virtual calls in the program.
    public final static boolean SOLVE_VCALLS = true;

    // Flag to check file descriptors during analysis.
    public final static boolean CHECK_FD = true;

    // Timeout threshold for running the analysis program, in seconds. If set to a value less than 0, there is no timeout.
    public final static int TIMEOUT = 10800; // TIMEOUT threshold (s) for running the analysis program. No timeout if this is <0

    // List of primary keywords used in the analysis.
    public final static String[] PRI_KEYWORDS = {"init", "on", "do", "create", "set", "is", "get", "dump", "~"};

}
