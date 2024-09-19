import analyze.Analyzer;
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
import util.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class main {

    // Analyzer instance to perform analysis
    public static Analyzer analyzer;

    // List to store paths of firmware files
    public static List<String> firmwarePath = new ArrayList<>();

    // Name of the firmware
    public static String firmwareName;

    // Start time of the analysis
    public static long startTime;

    // Time taken for the analysis
    public static long analysisTime;

    public static void main(String[] args) throws IOException, VersionException, CancelledException,
            DuplicateNameException, InvalidNameException, DemangledException {

        // Path to the program to be analyzed
        String programPath = args[0];
        
        // Extract the project directory name from the program path
        String[] pathParts = programPath.split(File.separator);
        String projectDirectoryName = Constants.OUTPUT_DIR + File.separator + pathParts[pathParts.length-2];

        GhidraProject ghidraProject;

        // Initialize the Ghidra application if not already initialized
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraJarApplicationLayout(), configuration);
        }

        // Create or open a Ghidra project
        String projectName = Constants.PROJECT_NAME;
        try {
            File dir = new File(projectDirectoryName);
            if (!dir.exists())
                dir.mkdirs();
            ghidraProject = GhidraProject.openProject(projectDirectoryName, projectName);
        } catch (IOException e) {
            // Create a new project if it does not exist
            ghidraProject = GhidraProject.createProject(projectDirectoryName, projectName, false);
        }

        // Set the name of the RIL (Radio Interface Layer) from the program path
        Global.rilName = programPath.split(File.separator)[programPath.split(File.separator).length-2];

        // Initialize the analyzer with the Ghidra project and program path
        analyzer = new Analyzer(ghidraProject, programPath);
        analyze(); // Perform analysis
        analyzer.releaseProgram(); // Release the program

        // Close the Ghidra project without deleting it
        ghidraProject.setDeleteOnClose(false);
        ghidraProject.close();
    }

    // Method to dump Pcode operations of functions to a file
    public static void dumpFuncPcodes(List<TaintSource> taintSources) throws FileNotFoundException, DemangledException {
        PrintStream termout = System.out;
        RILLog.debugLog("dumpFuncPcodes start");
        // Change output stream to a file
        PrintStream fs = new PrintStream(Constants.DIRECTORY_NAME + File.separator + "FuncPcodes.txt");
        System.setOut(fs);

        // Iterate over all functions in the program
        Iterator<Function> functionIterator = Global.getProgram().getFunctionManager().getFunctions(true);
        while (functionIterator.hasNext()) {
            Function func = functionIterator.next();
            RILLog.debugLog("Function: " + func.toString() + " at " + func.getEntryPoint().toString());

            // Decompile the function and get Pcode operations
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

        // Revert back to standard output
        System.setOut(termout);
        RILLog.debugLog("dumpFuncPcodes finish");
    }

    // Method to perform analysis
    public static void analyze() throws DemangledException, FileNotFoundException {
       AppendixUtil.tempAppendIndirectCall();
        // Optionally solve virtual calls
//        if (Config.SOLVE_VCALLS)
//            solveVCalls();

        // Retrieve all functions and perform taint analysis
        FunctionUtil.getAllFunctions(Global.getProgram());
        List<TaintSource> taintSources = new ArrayList<>();
        taintApis(taintSources);
//        dumpFuncPcodes(taintSources);
        taintAnalysis(taintSources);
    }

    // Method to resolve virtual function calls in the program
    public static void solveVCalls() {
        String TAG = "[solveVCalls] ";
        // Initialize logging for virtual table analysis
        RILLog.initLog("vtable");

        Program program = Global.getProgram();

        long start = System.currentTimeMillis();
        int decompiled_func = 0;

        // List of target mnemonics based on processor type and pointer size
        List<String> targetMnem = new ArrayList<>();
        if (program.getLanguage().getProcessor().toString().contains("AARCH") && Global.POINTER_SIZE == 8) {
            // ARM64 architecture
            targetMnem.add("blr");
            targetMnem.add("br");
        } else if (program.getLanguage().getProcessor().toString().equals("ARM") && Global.POINTER_SIZE == 4) {
            // ARM32 architecture
            targetMnem.add("blx");
            targetMnem.add("bx");
        }

        // Iterate over all functions in the program
        for (Function f : FunctionUtil.getAllFunctions(program)) {
            if (f.getParentNamespace().isGlobal()) { // Only consider functions not in the global namespace
                continue;
            }

            ++decompiled_func;
            DecompileResults dr = Global.getDecompFunc(f);
            if (dr == null)
                continue;
            HighFunction hf = dr.getHighFunction();
            Iterator<PcodeOpAST> pcode = hf.getPcodeOps();
            List<PcodeOpAST> pcodes = new ArrayList<>();

            // Collect CALLIND Pcode operations
            while (pcode.hasNext()) {
                PcodeOpAST current = pcode.next();
                if (current.getMnemonic().equals("CALLIND")) {
                    pcodes.add(current);
                }
            }

            // Solve virtual calls for each CALLIND Pcode operation
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
                        VCallUtil.addVCall(vfunction.getEntryPoint(), vCallSolver.address);
                    }
                }
            }
        }
        RILLog.debugLog("Time consumed (ms): " + (System.currentTimeMillis() - start));

        // Revert back to standard output
        System.setOut(System.out);
    }

    // Method to add taint sources for analysis
    public static void taintApis(List<TaintSource> taintSources) {
        taintSources.add(new TaintSource(Constants.C_READ, 0, List.of(1)));
        taintSources.add(new TaintSource(Constants.C_READ_CHK, 0, List.of(1)));
    }

    // Method to perform taint analysis
    public static void taintAnalysis(List<TaintSource> taintSources) throws FileNotFoundException {
        TaintEngine taintEngine = new TaintEngine();
        taintEngine.startBackwardTaint(taintSources);
        JSONObject jsonResult = taintEngine.getJsonResult();
    }

}
