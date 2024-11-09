package analyze;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.base.project.GhidraProject;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.*;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.test.TestProgramManager;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TimeoutTaskMonitor;
import util.NumericUtil;
import util.RILLog;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class Analyzer {

    public TestProgramManager programManager;
    public long size;
    public long analysisTime;
    public GhidraProject project;

    /**
     * Constructor for the Analyzer class.
     * Initializes the analysis process for a given program within a Ghidra project.
     *
     * @param project    The GhidraProject instance that manages the project.
     * @param programName The name of the program to analyze.
     * @throws VersionException       If there is a version mismatch.
     * @throws CancelledException     If the operation is cancelled.
     * @throws DuplicateNameException If a duplicate name is detected.
     * @throws InvalidNameException   If an invalid name is provided.
     * @throws IOException            If an I/O error occurs.
     */
    public Analyzer(GhidraProject project, String programName) throws VersionException, CancelledException, DuplicateNameException, InvalidNameException, IOException {

        RILLog.debugLog("Start analyzing " + programName);

        // Load the binary file.
        File file = new File(programName);
        size = file.length();
        if (!file.exists()) {
            throw new FileNotFoundException("Cannot find Program: " + programName);
        }

        programManager = new TestProgramManager();

        int index = programName.lastIndexOf(File.separator);
        String appName = programName.substring(index + 1);
        String pathName = programName.substring(0, index);
        Program program;
        try {
            // Try to open the analyzed program if it exists.
            program = project.openProgram(pathName, appName, false);
        } catch (FileNotFoundException | IllegalArgumentException e) {
            // Import the program if it doesn't exist.
            program = project.importProgram(file);
        }

        long base = program.getImageBase().getUnsignedOffset();

        // Initialize global environment variables.
        Global.program = program;
        Global.tag = program.getName() + "@" + program.getExecutableMD5();
        this.project = project;

        // Display the processor used by Ghidra.
        RILLog.debugLog("Language used: " + program.getLanguage().toString());

        // Initialize architecture-specific constants.
        initLanguageSpecificConst();

        long startTime = System.currentTimeMillis();
        if (GhidraProgramUtilities.shouldAskToAnalyze(program)) { // Check if the program has not been analyzed yet...
            // Start the analysis of the loaded binary file.
            int txId = program.startTransaction("Analysis");
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);

            mgr.initializeOptions();
            mgr.reAnalyzeAll(null);

            // Analysis might take some time.
            RILLog.debugLog("Analyzing...");
            mgr.startAnalysis(TimeoutTaskMonitor.timeoutIn(Config.DISASSEMBLE_TIMEOUT, TimeUnit.SECONDS));

            // Mark the program as analyzed.
            GhidraProgramUtilities.setAnalyzedFlag(program, true);
        }

        // Record the analysis time.
        analysisTime = System.currentTimeMillis() - startTime;

        // Start a timeout watcher to terminate if the analysis takes too long.
        startTimeoutWatcher(Config.TIMEOUT);
    }

    /**
     * Releases the program currently held by the program manager.
     */
    public void releaseProgram() {
        programManager.release(Global.program);
    }

    public void initLanguageSpecificConst() {
        Program program = Global.getProgram();
        CompilerSpec compilerSpec = program.getCompilerSpec();

        // init arch-specific pcode consts
        Global.LANGUAGE = program.getLanguage().toString();
        Global.POINTER_SIZE = program.getDefaultPointerSize();
        Global.STACK_REG = String.format("(register, %s, %d)",
                NumericUtil.longToHexString(compilerSpec.getStackPointer().getOffset()), Global.POINTER_SIZE);
    }


    public static void startTimeoutWatcher(int sec) {
        if (sec < 0)
            return;
        Thread t = new Thread() {
            public void run() {
                try {
                    Thread.sleep(sec * 1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                RILLog.errorLog("TimeOut");
                System.exit(1);
            }
        };
        t.setDaemon(true);
        t.start();
    }
}
