import analyze.Analyzer;
import analyze.Config;
import analyze.Constants;
import analyze.Global;
import ghidra.GhidraJarApplicationLayout;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.demangler.DemangledException;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import org.json.JSONObject;
import taint.TaintEngine;
import taint.TaintSource;
import taint.VCallSolver;
import util.Decompiler;
import util.FunctionUtil;
import util.RILLog;
import util.VCallUtil;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * The main class for the analysis application, responsible for initializing the Ghidra environment,
 * performing various analyses, and managing virtual function calls and taint analysis.
 */
public class main {

    public static Analyzer analyzer;
    public static List<String> firmwarePath = new ArrayList<>();
    public static String firmwareName;
    public static long startTime;
    public static long analysisTime;

    /**
     * Main entry point for the application.
     * Initializes the Ghidra environment, opens or creates a project, and performs analysis.
     *
     * @param args Command line arguments; the first argument is the path to the program to analyze.
     */
    public static void main(String[] args) throws IOException, VersionException, CancelledException,
            DuplicateNameException, InvalidNameException, DemangledException {
        // Path to the program to be analyzed
        String programPath = args[0];
        String[] pathParts = programPath.split(File.separator);

        // Define Ghidra project directory
        String projectDirectoryName = Constants.OUTPUT_DIR + File.separator + pathParts[pathParts.length - 2];

        GhidraProject ghidraProject;

        // Initialize Ghidra application if not already initialized
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraJarApplicationLayout(), configuration);
        }

        // Open or create a Ghidra project
        String projectName = Constants.PROJECT_NAME;
        try {
            File dir = new File(projectDirectoryName);
            if (!dir.exists())
                dir.mkdirs();
            ghidraProject = GhidraProject.openProject(projectDirectoryName, projectName);
        } catch (IOException e) {
            // Create project if it does not exist
            ghidraProject = GhidraProject.createProject(projectDirectoryName, projectName, false);
        }

        // Set the global RIL name from the program path
        Global.rilName = programPath.split(File.separator)[programPath.split(File.separator).length - 2];

        // Initialize the analyzer and perform analysis
        analyzer = new Analyzer(ghidraProject, programPath);
        analyze();
        analyzer.releaseProgram();

        // Close the Ghidra project
        ghidraProject.setDeleteOnClose(false);
        ghidraProject.close();
    }

    /**
     * Dumps the Pcode operations for all functions in the program to a file.
     * This function is used for debugging and analysis of Pcode operations.
     *
     * @param taintSources A list of taint sources, which is not used in this method but required as a parameter.
     * @throws FileNotFoundException If the output file cannot be created.
     * @throws DemangledException   If there is an error during demangling.
     */
    public static void dumpFuncPcodes(List<TaintSource> taintSources) throws FileNotFoundException, DemangledException {
        PrintStream termout = System.out;
        RILLog.debugLog("dumpFuncPcodes start");

        // Change output stream to file
        PrintStream fs = new PrintStream(Constants.DIRECTORY_NAME + File.separator + "FuncPcodes.txt");
        System.setOut(fs);

        // Iterate through all functions in the program
        Iterator<Function> functionIterator = Global.getProgram().getFunctionManager().getFunctions(true);
        while (functionIterator.hasNext()) {
            Function func = functionIterator.next();
            RILLog.debugLog("Function: " + func.toString() + " at " + func.getEntryPoint().toString());

            // Decompile function and lift to Pcodes
            DecompileResults dr = Global.getDecompFunc(func);
            if (dr == null)
                continue;

            HighFunction hf = dr.getHighFunction();
            Iterator<PcodeOpAST> pcode = hf.getPcodeOps();
            while (pcode.hasNext()) {
                PcodeOpAST current = pcode.next();
                RILLog.debugLog("\t" + current.toString());
            }
        }

        // Revert output stream back to stdout
        System.setOut(termout);
        RILLog.debugLog("dumpFuncPcodes finish");
    }

    /**
     * Perform various analyses on the program.
     * This includes solving virtual function calls, taint analysis, etc.
     *
     * @throws DemangledException If there is an error during demangling.
     * @throws FileNotFoundException If the output files cannot be created.
     */
    public static void analyze() throws DemangledException, FileNotFoundException {
        if (Config.SOLVE_VCALLS) {
            solveVCalls();
        }

        List<TaintSource> taintSources = new ArrayList<>();
        taintApis(taintSources);
//        dumpFuncPcodes(taintSources);
        taintAnalysis(taintSources);
//        taintVCallsApis(taintSources);
    }

    /**
     * Solves virtual function calls in the program.
     * This method resolves virtual function calls and populates the VCallUtil with the results.
     */
    public static void solveVCalls() {
        String TAG = "[solveVCalls] ";
        RILLog.initLog("vtable");

        Program program = Global.getProgram();
        long start = System.currentTimeMillis();
        int decompiled_func = 0;

        List<String> targetMnem = new ArrayList<>();
        if (program.getLanguage().getProcessor().toString().contains("AARCH") && Global.POINTER_SIZE == 8) {
            // ARM64
            targetMnem.add("blr");
            targetMnem.add("br");
        } else if (program.getLanguage().getProcessor().toString().equals("ARM") && Global.POINTER_SIZE == 4) {
            // ARM32
            targetMnem.add("blx");
            targetMnem.add("bx");
        }

        // Iterate through all functions in the program
        for (Function f : FunctionUtil.getAllFunctions(program)) {
            if (f.getParentNamespace().isGlobal()) {
                // Only consider non-global functions (likely virtual tables)
                continue;
            }

            ++decompiled_func;
            DecompileResults dr = Global.getDecompFunc(f);
            if (dr == null)
                continue;

            HighFunction hf = dr.getHighFunction();
            Iterator<PcodeOpAST> pcode = hf.getPcodeOps();
            List<PcodeOpAST> pcodes = new ArrayList<>();
            List<Address> vCallAddrs = new ArrayList<>();

            // Collect Pcode operations with mnemonic "CALLIND"
            while (pcode.hasNext()) {
                PcodeOpAST current = pcode.next();
                if (current.getMnemonic().equals("CALLIND")) {
                    pcodes.add(current);
                }
            }

            // Process each collected Pcode operation
            for (PcodeOpAST pcodeOpAST : pcodes) {
                VCallSolver vCallSolver = new VCallSolver(program, hf, pcodeOpAST);
                vCallSolver.solve();
                List<Function> vFunctions = vCallSolver.getvFunctions();
                if (vFunctions != null && !vFunctions.isEmpty()) {
                    for (Function vfunction : vFunctions) {
                        RILLog.debugLog(TAG + vCallSolver.funcName +
                                " ==> " + vfunction.toString() +
                                "\t" + vCallSolver.getAddress() +
                                " ==> " + vfunction.getEntryPoint());
                        // Add virtual function call mappings
                        VCallUtil.addVCall(vfunction.getEntryPoint(), vCallSolver.address);
                    }
                }
            }
        }
        RILLog.debugLog("Time consumed (ms): " + (System.currentTimeMillis() - start));
        System.setOut(System.out);
    }

    /**
     * Defines taint sources for the analysis.
     *
     * @param taintSources A list to which taint sources will be added.
     */
    public static void taintApis(List<TaintSource> taintSources) {
        taintSources.add(new TaintSource(Constants.C_WRITE, 0, List.of(1)));
        taintSources.add(new TaintSource(Constants.C_WRITE_CHUNK, 0, List.of(1)));
    }

    /**
     * Performs taint analysis based on the defined taint sources.
     *
     * @param taintSources A list of taint sources used for the analysis.
     * @throws FileNotFoundException If the output file cannot be created.
     */
    public static void taintAnalysis(List<TaintSource> taintSources) throws FileNotFoundException {
        TaintEngine taintEngine = new TaintEngine();
        taintEngine.startBackwardTaint(taintSources);
        JSONObject jsonResult = taintEngine.getJsonResult();
    }
}
