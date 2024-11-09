package taint;

import analyze.Config;
import analyze.Constants;
import analyze.Global;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import org.json.JSONObject;
import util.*;
import util.FunctionUtil;
import util.PCodeUtil;
import util.RILLog;
import taint.VCallSolver;

import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.util.*;

public class TaintEngine {

    // Starting address for taint propagation
    Address start;
    // List of taint sources to be analyzed
    List<TaintSource> taintSources;
    // Expression used for taint analysis
    String taintExpression;
    // Paths traced during taint analysis
    List<TaintPath> paths;
    // Mapping of input locations with their taint expressions
    HashMap<Address, String> inputLocations;
    // JSON object to store the results of taint analysis
    public JSONObject jsonResult = new JSONObject();
    // Output string for storing results
    public String outputStr = "";
    // Command channel for logging and interaction
    CmdChannel cmdChannel;

    // Program being analyzed
    Program program;

    // List of exported functions
    ArrayList<Address> exportedFuncs = new ArrayList<Address>();
    // List of taint results
    List<TaintResult> results = new ArrayList<>();

    /**
     * Constructor to initialize TaintEngine with start address and taint expression.
     *
     * @param startAdd Address to start the taint analysis
     * @param taintExp Taint expression to use
     */
    public TaintEngine(Address startAdd, String taintExp) {
        start = startAdd;
        taintExpression = taintExp;
        paths = new ArrayList<>();
        inputLocations = new HashMap<>();
        program = Global.getProgram();

        // Initialize command channel and logging if configuration requires
        if (Config.CHECK_FD) {
            RILLog.initLog("CmdChannel");
            cmdChannel = new CmdChannel();
        }
    }

    /**
     * Default constructor initializing TaintEngine.
     */
    public TaintEngine() {
        program = Global.getProgram();
        if (Config.CHECK_FD) {
            RILLog.initLog("CmdChannel");
            cmdChannel = new CmdChannel();
        }
    }

    /**
     * Starts the backward taint analysis from a list of taint sources.
     *
     * @param taintSources List of taint sources to be analyzed
     * @throws FileNotFoundException If a required file is not found
     */
    public void startBackwardTaint(List<TaintSource> taintSources) throws FileNotFoundException {
        // Tag for logging
        String TAG = "[startBackwardTaint] ";
        for (TaintSource ts : taintSources) {
            // Check for null address in the taint source
            if (ts.address == null) {
                RILLog.initLog("LOG.txt." + ts.getName());
                RILLog.debugLog(TAG + "ts.address is null");
                continue;
            }
            RILLog.initLog("LOG.txt." + ts.getName() + "." + ts.address.toString());

            Address startAddress = ts.address;
            RILLog.debugLog(TAG + "handling address: " + startAddress.toString());

            // Initialize taint path for the current taint source
            TaintPath tp = new TaintPath(ts.fd_arg, FunctionUtil.getFunctionWith(program, startAddress), ts.args);
            tp.addToPath(startAddress);

            // Start analyzing function calls and jumps
            interFunctionCallJump(startAddress, tp, 0);

            RILLog.debugLog(TAG + "TaintSource analysis finished");
            // Revert back to stdout
            System.setOut(System.out);
        }
    }

    /**
     * Handles inter-function calls and jumps in taint analysis.
     *
     * @param start Start address for taint analysis
     * @param taintPath Current taint path
     * @param level Current recursion level
     */
    private void interFunctionCallJump(Address start, TaintPath taintPath, int level) {
        final String TAG = "[interFunctionJump] ";

        // Prevent stack overflow by limiting recursion depth
        if (level >= Config.MAX_FUNCTION_JUMP) {
            RILLog.errorLog(TAG + " exceeding max function jump limit, exiting");
            return; // prevent stack overflow
        }

        List<Address> toBeTainted = new ArrayList<>();

        // Get references to the current address
        ReferenceIterator rawRefs = AddressUtil.getReferenceToAddress(program, start);
        ArrayList<Reference> refs = getExclusiveRef(rawRefs);
        RILLog.debugLog(TAG + "Handling ref to " + start);
        for (Reference curRef : refs) {
            // Get reference address and handle it based on its type
            Address curRefAddr = curRef.getFromAddress();
            if (curRef.isEntryPointReference()) {
                RILLog.debugLog(TAG + curRefAddr + " ref is an Entry Point");
                continue;
            } else if (curRef.getReferenceType().isData()) {
                // Handle virtual function call references
                RILLog.debugLog(TAG + curRefAddr + " ref is Data(Virtual Table)");
                handleVTableRef(curRefAddr, toBeTainted);
                continue;
            } else if (curRef.getReferenceType().isIndirect()) {
                RILLog.debugLog(TAG + curRefAddr + " ref is Indirect(Virtual Table)");
                continue;
            } else {
                toBeTainted.add(curRefAddr);
            }
        }

        // Add virtual function calls
        if (VCallUtil.vCalls.keySet().contains(start)) {
            List<Address> vCallSites = VCallUtil.vCalls.get(start);
            for (Address vCallAddress : vCallSites) {
                toBeTainted.add(vCallAddress);
                RILLog.debugLog(TAG + String.format("adding virtual call 0X%x ==> 0X%x", start.getUnsignedOffset(), vCallAddress.getUnsignedOffset()));
            }
        }

        // Add appendix function calls
        List<Address> appendixCaller = AppendixUtil.getCalleeAddr(start);
        if (appendixCaller != null) {
            for (Address address : appendixCaller) {
                toBeTainted.add(address);
                RILLog.debugLog(TAG + String.format("adding appending call 0X%x ==> 0X%x", start.getUnsignedOffset(), address.getUnsignedOffset()));
            }
        }

        RILLog.debugLog("\n\n");

        // Finish taint analysis if no more addresses to taint
        if (toBeTainted.isEmpty()) {
            taintFinish(taintPath);
        } else {
            // Recursively handle each address to be tainted
            for (Address addr : toBeTainted) {
                if (taintPath.containsPath(addr))
                    continue; // prevent recursion
                intraFunctionBackwardTaint(addr, taintPath.clone(), level);
            }
        }
    }


    /**
     * Handles the taint propagation for virtual table references.
     * Currently, this method is reserved for future implementation.
     *
     * @param addr Address of the virtual table reference
     * @param toBeTainted List of addresses that will be tainted
     */
    private void handleVTableRef(Address addr, List<Address> toBeTainted) {
        String TAG = "[handleVTableRef] ";
        RILLog.debugLog(TAG + "reserved");
        assert 0 > 1; // Placeholder for future implementation
    }

    /**
     * Performs backward taint analysis within a function.
     *
     * @param start Address to start the taint analysis
     * @param taintPath Current taint path being analyzed
     * @param level Current recursion level in function calls
     */
    public void intraFunctionBackwardTaint(Address start, TaintPath taintPath, int level) {
        final String TAG = "[intraFunctionBackwardTaint] ";
        List<Integer> argIndex = new ArrayList<>(taintPath.taintArgs);

        // Check if the start address is null
        if (start == null) {
            RILLog.errorLog(TAG + " Start address is null");
            return;
        }

        // Retrieve the function at the start address
        Function func = FunctionUtil.getFunctionWith(program, start);

        // Check if the function is null or should be excluded based on its name
        if (func == null) {
            RILLog.errorLog(TAG + " function at " + start + " is null");
            return;
        }
        if (func.toString().contains("Async") || func.toString().contains("SockUnixIoChannel")) {
            return; // Skip certain functions to avoid unnecessary analysis
        }

        // Check if the function is in the blacklist
        for (String blFunc : Constants.funcBlackList) {
            if (func.getName().contains(blFunc))
                return; // Skip blacklisted functions to prevent branch explosion
        }

        RILLog.debugLog(TAG + " at function " + func.getName() + " entry point " + start);
        HighFunction hf = Global.getDecompFunc(func).getHighFunction();

        // Identify the Pcode operation at the taint starting point
        Iterator<PcodeOpAST> startPcodeOpAST = hf.getPcodeOps(start);
        PcodeOp startPcodeOp = null;
        if (startPcodeOpAST.hasNext()) {
            startPcodeOp = startPcodeOpAST.next();
            RILLog.debugLog(TAG + "find startPcodeOp by addr: " + startPcodeOp.toString());
        } else {
            // Handle cases where address-specific PcodeOp is not found
            startPcodeOpAST = hf.getPcodeOps(); // Fallback for trunked functions
            while (startPcodeOpAST.hasNext()) {
                startPcodeOp = startPcodeOpAST.next();
                if (startPcodeOp.getMnemonic().equals("CALL") || startPcodeOp.getMnemonic().equals("CALLIND")) {
                    RILLog.debugLog(TAG + "find startPcodeOp: " + startPcodeOp.toString());
                    break;
                }
            }
        }

        // Check if a valid PcodeOp was found
        if (startPcodeOp == null) {
            RILLog.errorLog(TAG + start + " has no pcodeopast");
            return;
        }
        RILLog.debugLog(TAG + "pcodeOp has inputs number " + startPcodeOp.getNumInputs());
        for (int idx : argIndex) { // Check if the number of inputs is sufficient
            if (startPcodeOp.getNumInputs() < idx + 1) {
                RILLog.debugLog(TAG + "fund definition has not enough arguments");
                return;
            }
        }

        // Extract taint arguments as variable nodes and update the taint path
        taintPath.addToTrace(startPcodeOp);
        taintPath.addToPath(start);

        // Check file descriptor verification if required by configuration
        if (Config.CHECK_FD) {
            if (!cmdChannel.verifyFd(hf, startPcodeOp, taintPath)) {
                return;
            }
        }

        // Start backward taint analysis on variable nodes
        for (int i = 0; i < taintPath.taintArgs.size(); i++) {
            Varnode node = startPcodeOp.getInput(taintPath.getArgIndex(i) + 1); // Note: +1 for the first parameter (MEM)
            taintPath.addToTraceNode(startPcodeOp, node);
            taintSingleStep(hf, node, i, taintPath); // Recursively analyze the node
        }

        RILLog.debugLog(taintPath.printPath() + "\n" + taintPath.printTrace() + "\n");

        // Check if taint analysis is complete
        if (isTaintFinished(taintPath)) {
            taintFinish(taintPath);
        } else {
            // Continue analysis with function callers
            interFunctionCallJump(func.getEntryPoint(), taintPath, level + 1);
        }
    }

    /**
     * Performs forward taint analysis starting from a variable node.
     *
     * @param node Variable node to start the forward analysis
     * @param startPcodeOp Pcode operation where the node is used
     * @param taintPath Current taint path
     */
    private void taintForward(Varnode node, PcodeOp startPcodeOp, TaintPath taintPath) {
        String TAG = "[taintForward] ";
        boolean found = false;
        String nodeStr = PCodeUtil.evaluateVarNode(node);
        RILLog.debugLog(TAG + "node:" + node.toString());
        RILLog.debugLog(TAG + "nodeStr evaluated: " + nodeStr);
        ArrayList<PcodeBlockBasic> cachedBasicBlocks = new ArrayList<PcodeBlockBasic>(); // To avoid loop

        // Walk through all users of the variable node indicating forward analysis
        PcodeBlockBasic pcodeBlockBasic = startPcodeOp.getParent();
        cachedBasicBlocks.add(pcodeBlockBasic);
        Iterator<PcodeOp> pcodeOpIterator = pcodeBlockBasic.getIterator();
        // Future work: Handle cases where the startPcodeOp needs special handling
        Function func = FunctionUtil.getFunctionWith(program, startPcodeOp.getSeqnum().getTarget());
        Address funcAddr = func.getEntryPoint();
        RILLog.debugLog(TAG + "taintBasicBlock left: " + pcodeBlockBasic.getStart().toString());
        HighFunction highFunction = Global.getDecompFunc(func).getHighFunction();
        taintBasicBlock(pcodeOpIterator, nodeStr, startPcodeOp.getInput(0).toString(), taintPath.clone(), highFunction);

        RILLog.debugLog(TAG + "continue to subsequentBB: " + pcodeBlockBasic.getStart().toString());
        // Iterate through subsequent basic blocks
        taintSubsequentBB(pcodeBlockBasic, cachedBasicBlocks, nodeStr, startPcodeOp.getInput(0).toString(), taintPath.clone(), highFunction);
    }


    /**
     * Recursively taints subsequent basic blocks in the control flow graph starting from the given basic block.
     *
     * @param pcodeBlockBasic The starting basic block to begin the tainting process.
     * @param cachedBasicBlocks A list to keep track of basic blocks that have already been processed to avoid reprocessing.
     * @param nodeStr A string used to identify specific nodes or elements to be tainted.
     * @param filterStr A filter string to exclude specific nodes or elements from being tainted.
     * @param taintPath The current taint path that keeps track of the propagation of taint through the control flow graph.
     * @param highFunction The high-level function object that contains information about the current function and its operations.
     */
    private void taintSubsequentBB(PcodeBlockBasic pcodeBlockBasic, ArrayList<PcodeBlockBasic> cachedBasicBlocks, String nodeStr, String filterStr, TaintPath taintPath, HighFunction highFunction){
        String TAG = "[taintSubsequentBB] ";
        
        // Get the number of outgoing edges from the current basic block
        int size = pcodeBlockBasic.getOutSize();
        RILLog.debugLog(TAG + "outSize: " + size);
        
        // Iterate through each outgoing edge
        for(int i = 0; i < size; i++){
            // Retrieve the next basic block in the control flow graph
            PcodeBlock followupPcodeBlock = pcodeBlockBasic.getOut(i);
            RILLog.debugLog(TAG + "handle out " + i);
            
            // Check if the next block is an instance of PcodeBlockBasic
            if (followupPcodeBlock instanceof PcodeBlockBasic) {
                // Cast to PcodeBlockBasic for further processing
                PcodeBlockBasic followupPcodeBasicBlock = (PcodeBlockBasic) followupPcodeBlock;
                RILLog.debugLog(TAG + "followupPcodeBasicBlock: " + followupPcodeBasicBlock.getStart().toString());
                
                // Check if this block has already been processed
                if(cachedBasicBlocks.contains(followupPcodeBasicBlock)){
                    RILLog.debugLog(TAG + "cached");
                    continue; // Skip processing if already cached
                } else {
                    // Add this block to the cache to avoid reprocessing
                    cachedBasicBlocks.add(followupPcodeBasicBlock);
                }
                
                // Get an iterator for the Pcode operations in the follow-up basic block
                Iterator<PcodeOp> followupPcodeBasicBlockIterator = followupPcodeBasicBlock.getIterator();
                
                // Taunt the basic block by iterating through its Pcode operations
                taintBasicBlock(followupPcodeBasicBlockIterator, nodeStr, filterStr, taintPath, highFunction);
                
                // Recursively taint subsequent basic blocks
                taintSubsequentBB(followupPcodeBasicBlock, cachedBasicBlocks, nodeStr, filterStr, taintPath, highFunction);
            }
        }
    }


    private void taintBasicBlock(Iterator<PcodeOp> pcodeOpIterator, String nodeStr, String filterStr, TaintPath taintPath, HighFunction highFunction){
        String TAG = "[taintBasicBlock] ";
        RILLog.debugLog(TAG + "nodeStr: " + nodeStr + " filterStr: " + filterStr);
        while(pcodeOpIterator.hasNext()){
            PcodeOp pcodeOp = pcodeOpIterator.next();
            String mnem = pcodeOp.getMnemonic();
            int num = pcodeOp.getNumInputs();
            boolean found = false;
            Function func = null;
            switch(mnem){
                case "CALL":
                    RILLog.debugLog(TAG + "find CALL: (" + pcodeOp.getSeqnum().getTarget().toString() + ") " + pcodeOp.toString());
                    Address addr = pcodeOp.getInput(0).getAddress();
                    func = FunctionUtil.getFunctionWith(program, addr);
                    RILLog.debugLog(TAG + "called func: (" + addr.toString() + ") " + func.toString());
                    if(Constants.funcBlackList.contains(func.toString())){
                        RILLog.debugLog(TAG + "ignored black func: " + func.toString());
                        continue;
                    }
                    if(func != null){
                        if(func.isExternal() || (func.getThunkedFunction(true) != null && func.getThunkedFunction(true).isExternal())){
                            RILLog.debugLog(TAG + "func is external");
                            TaintPath newTaintPath = taintPath.clone();
                            newTaintPath.addToForwardTrace(pcodeOp);
                            forwardFinished(newTaintPath);
                            break;
                        }
                    }
                    for(int i = 1; i < num; i++){
                        Varnode input = pcodeOp.getInput(i);
                        String inputStr = PCodeUtil.evaluateVarNode(input);
                        RILLog.debugLog(TAG + "input " + i + " : " + inputStr);
                        if(inputStr.contains(nodeStr) && (filterStr == null || !inputStr.contains(filterStr))){
                            RILLog.debugLog(TAG + "hit param " + i);
                            TaintPath newTaintPath = taintPath.clone();
                            RILLog.debugLog(TAG + "updateForwardArg: [0]" + newTaintPath.getForwardArgIndex(0) + " to " + (i-1));
                            newTaintPath.updateForwardArg(0, i-1);
                            newTaintPath.addToForwardTrace(pcodeOp);
                            RILLog.debugLog(TAG + "addToForwardTrace: (" + pcodeOp.getSeqnum().getTarget().toString() + ") " + pcodeOp.toString());
                            taintForwardFunc(addr, newTaintPath);
                            found = true;
                            break;
                        }
                    }
                    if(!found){ // TODO: for condition param is stored to other param, like "this"
                        if(pcodeOp.getNumInputs() == 2){
                            Varnode inputNode = pcodeOp.getInput(1);
                            String inputNodeStr = PCodeUtil.evaluateVarNode(inputNode);
                            Varnode thisNode = highFunction.getLocalSymbolMap().getParamSymbol(0).getHighVariable().getRepresentative();
                            String thisNodeStr = PCodeUtil.evaluateVarNode(thisNode);
                            if(thisNode.getHigh().getName().equals("this") && inputNodeStr.contains(thisNodeStr)){
                                RILLog.debugLog(TAG + "track representation of this, maybe false positive");
                                TaintPath newTaintPath = taintPath.clone();
                                RILLog.debugLog(TAG + "updateForwardArg: [0]" + newTaintPath.getForwardArgIndex(0) + " to 0(this)");
                                newTaintPath.updateForwardArg(0, 0);
                                newTaintPath.addToForwardTrace(pcodeOp);
                                RILLog.debugLog(TAG + "addToForwardTrace: (" + pcodeOp.getSeqnum().getTarget().toString() + ") " + pcodeOp.toString());
                                taintForwardFunc(addr, newTaintPath);
                            }else{
                                RILLog.debugLog(TAG + "ignore no match param with this");
                            }
                        }else{
                            RILLog.debugLog(TAG + " unhandled input nums");
                        }
                    }
                    break;
                case "CALLIND":
                    RILLog.debugLog(TAG + "find CALLIND: (" + pcodeOp.getSeqnum().getTarget().toString() + ") " + pcodeOp.toString());
                    List<Address> targets = new ArrayList<Address>();
                    List<Address> vCallTargets = new ArrayList<>();
                    if(highFunction.getFunction().toString().equals("IpcModem::ProcessSingleIpcMessageReceived")){
                        if(PCodeUtil.evaluateVarNode(pcodeOp.getInput(0)).endsWith("(const, 0x20, 8)")){
                            vCallTargets.addAll(FunctionUtil.addrGetRxDatas);
                        }
                    } else if (highFunction.getFunction().getName().equals("GetRxData")) {
                        RILLog.debugLog("");
                        PcodeOp dispatchOp = pcodeOp.getInput(0).getDef();
                        if(dispatchOp.getMnemonic().equals("MULTIEQUAL")){
                            for(Varnode caseNode : dispatchOp.getInputs()){
                                PcodeOp caseOp = caseNode.getDef();
                                boolean extract = true;
                                while(extract){
                                    switch (caseOp.getMnemonic()){
                                        case "LOAD":
                                            caseOp = caseOp.getInput(1).getDef();
                                            break;
                                        case "CAST":
                                            caseOp = caseOp.getInput(0).getDef();
                                            break;
                                        case "INT_ADD":
                                            Namespace namespace = null;
                                            Varnode baseClassNode = caseOp.getInput(0);
                                            if(!PCodeUtil.evaluateVarNode(baseClassNode).contains("PTRADD")){
                                                namespace = highFunction.getFunction().getParentNamespace();
                                                long offset = caseOp.getInput(1).getOffset();
                                                Function funcTar = VCallSolver.getVFuncWithOffset(namespace, offset);
                                                vCallTargets.add(funcTar.getEntryPoint());
                                            }
                                            extract = false;
                                            break;
                                        default:
                                            assert 1==0 : "new caseOp menm";
                                    }
                                }
                                if(caseOp.getMnemonic().equals("INT_ADD")){

                                }
                            }
                        }
                    }
                    if(vCallTargets.isEmpty()){
                        List<Address> temp = VCallUtil.getVCallsRevValue(pcodeOp.getSeqnum().getTarget());
                        if(temp != null && temp.size() > 0){
                            vCallTargets.addAll(temp);
                        }
                    }
                    if(!vCallTargets.isEmpty()){
                        targets.addAll(vCallTargets);
                    }
                    List<Address> appendixTargets = AppendixUtil.getCallerAddr(pcodeOp.getSeqnum().getTarget());
                    if(appendixTargets != null){
                        targets.addAll(appendixTargets);
                    }
                    for(Address target : targets){
                        RILLog.debugLog(TAG + "handle target:" + target.toString());
                        func = FunctionUtil.getFunctionWith(program, target);
                        if(Constants.funcBlackList.contains(func.toString())){
                            RILLog.debugLog(TAG + "ignored black func: " + func.toString());
                            continue;
                        }
                        if(func != null){
                            if(func.isExternal() || (func.getThunkedFunction(true) != null && func.getThunkedFunction(true).isExternal())){
                                RILLog.debugLog(TAG + "func is external");
                                TaintPath newTaintPath = taintPath.clone();
                                newTaintPath.addToForwardTrace(pcodeOp);
                                forwardFinished(newTaintPath);
                                continue;
                            }
                        }
                        found = false;
                        for(int i = 1; i < num; i++){
                            Varnode input = pcodeOp.getInput(i);
                            String inputStr = PCodeUtil.evaluateVarNode(input);
                            RILLog.debugLog(TAG + "input " + i + " is " + inputStr);
                            if(inputStr.contains(nodeStr) && (filterStr == null || !inputStr.contains(filterStr))){
                                RILLog.debugLog(TAG + "hit param " + i);
                                TaintPath newTaintPath = taintPath.clone();
                                RILLog.debugLog(TAG + "updateForwardArg: [0]" + newTaintPath.getForwardArgIndex(0) + " to " + (i-1));
                                newTaintPath.updateForwardArg(0, i-1);
                                newTaintPath.addToForwardTrace(pcodeOp);
                                RILLog.debugLog(TAG + "addToForwardTrace: (" + pcodeOp.getSeqnum().getTarget().toString() + ") " + pcodeOp.toString());
                                taintForwardFunc(target, newTaintPath);
                                found = true;
                                break;
                            }
                        }
                        if(!found){ // for condition param is stored to other param, like "this"
                            if(pcodeOp.getNumInputs() >= 2){
                                RILLog.debugLog(TAG + "track representation of this, maybe false positive");
                                TaintPath newTaintPath = taintPath.clone();
                                RILLog.debugLog(TAG + "updateForwardArg: [0]" + newTaintPath.getForwardArgIndex(0) + " to 0(this)");
                                newTaintPath.updateForwardArg(0, 0);
                                newTaintPath.addToForwardTrace(pcodeOp);
                                RILLog.debugLog(TAG + "addToForwardTrace: (" + pcodeOp.getSeqnum().getTarget().toString() + ") " + pcodeOp.toString());
                                taintForwardFunc(target, newTaintPath);
                            }else{
                                RILLog.debugLog(TAG + " unhandled input nums");
                            }
                        }
                    }
                    break;
                default:
                    continue;
            }
        }
        RILLog.debugLog(TAG + "returned");
    }

    /**
     * Taints the function at the specified address and updates the taint path with the new taint propagation information.
     *
     * @param funcAddr The address of the function to be tainted.
     * @param taintPath The current taint path that keeps track of the propagation of taint.
     */
    private void taintForwardFunc(Address funcAddr, TaintPath taintPath){
        String TAG = "[taintForwardFunc] ";

        // Retrieve the function associated with the given address
        Function function = FunctionUtil.getFunctionWith(program, funcAddr);

        // Check if the function is in the blacklist; if so, skip processing
        if(Constants.funcBlackList.contains(function.toString())){
            RILLog.debugLog(TAG + function.toString() + " in BlackList");
            return;
        }

        RILLog.debugLog(TAG + "funcAddr: " + funcAddr.toString() + " is " + function.toString());
        
        // Get the high-level function representation
        HighFunction highFunction = Global.getDecompFunc(function).getHighFunction();
        Varnode paramNode = null;
        
        try {
            // Retrieve the parameter node based on the taint path index
            paramNode = highFunction.getLocalSymbolMap().getParamSymbol(taintPath.getForwardArgIndex(0)).getHighVariable().getRepresentative();
        } catch (ArrayIndexOutOfBoundsException e) {
            // Log an error if the parameter index is out of bounds
            RILLog.errorLog(TAG + "param Index OOB");
            return;
        }

        RILLog.debugLog(TAG + "paramNode : [" + taintPath.getForwardArgIndex(0) + "] " + paramNode.toString());
        
        // Evaluate the string representation of the parameter node
        String paramStr = PCodeUtil.evaluateVarNode(paramNode);
        RILLog.debugLog(TAG + "paramStr evaluated: " + paramStr);
        
        // Retrieve all basic blocks in the high-level function
        ArrayList<PcodeBlockBasic> pcodeBlockBasicArrayList = highFunction.getBasicBlocks();
        // Taunt each basic block
        for(PcodeBlockBasic pcodeBlockBasic : pcodeBlockBasicArrayList){
            RILLog.debugLog(TAG + "taintBasicBlock: " + pcodeBlockBasic.getStart().toString());
            taintBasicBlock(pcodeBlockBasic.getIterator(), paramStr, null, taintPath.clone(), highFunction);
        }
    }

    /**
     * Logs the paths traced by the taint process, including both the backward and forward paths.
     *
     * @param taintPath The taint path object containing the trace and forward trace.
     */
    private void forwardFinished(TaintPath taintPath){
        String TAG = "[forwardFinished] ";
        String backwardPath = "[read] => ";
        
        // Construct the backward path string from the trace
        for(int i = 0; i < taintPath.trace.size(); i++){
            PcodeOp pcodeOp = taintPath.trace.get(i);
            Address addr = pcodeOp.getSeqnum().getTarget();
            Function func = FunctionUtil.getFunctionWith(program, addr);
            backwardPath += "[" + func.toString() + "]" + "(" + addr.toString() + ")";
            backwardPath += " => ";
        }
        RILLog.debugLog(TAG + "backward path: " + backwardPath);

        String forwardPath = "";
        
        // Construct the forward path string from the forward trace
        for(int i = 0; i < taintPath.forwardTrace.size(); i++){
            PcodeOp pcodeOp = taintPath.forwardTrace.get(i);
            Address addr = pcodeOp.getSeqnum().getTarget();
            Function func = FunctionUtil.getFunctionWith(program, addr);
            forwardPath += "[" + func.toString() + "]";
            forwardPath += " => ";
        }
        RILLog.debugLog(TAG + "forward path: " + forwardPath);
    }

    /**
     * Determines if the taint process has finished based on the taint path.
     *
     * @param taintPath The taint path object used to check the taint status.
     * @return True if the tainting process is complete, false otherwise.
     */
    private boolean isTaintFinished(TaintPath taintPath){
        // Check if there are no taint arguments left to process
        if(taintPath.getTaintArgNum() == 0){
            return false;
        }
        
        // Check if all taint arguments have been processed
        for(int i = 0; i < taintPath.taintArgs.size(); i++){
            if(taintPath.getArgIndex(i) != -1){
                return false;
            }
        }
        return true;
    }


    private void taintSingleStep(HighFunction hf, Varnode node, int idx, TaintPath taintPath) {
        final String TAG = "[taintSignleStep] ";

        if (node == null) {
            RILLog.errorLog(TAG + " VarNode is null");
            return;
        }

        if (node.isConstant()) {
            // Constant: directly solved node value and remove it from taint path
            long val = node.getAddress().getUnsignedOffset();
            taintPath.putResult(idx, val);
            taintPath.removeArg(idx);
            RILLog.debugLog(TAG + node.getAddress() + " constant taint propagation: arg idx " + taintPath.getArgIndex(idx) + " ==> " + val);
        }
        else if (node.isRegister()) {
            // Register: need to continue to trace in the function caller
            // Case 1: check if node is a function parameter
            boolean solved = solveFuncParam(node, idx, hf, taintPath);

            if (!solved) {
                // Case 2: node is an intermediate register, solve it as a stack reg
                String exp = PCodeUtil.evaluateVarNode(node);
                String targetExp = PCodeUtil.removeLoadPcodeExp(exp);

                if (targetExp.contains(Global.STACK_REG)) {
                    // common case: stack variable
                    RILLog.debugLog(TAG + node.getAddress() + " stack taint propagation: arg idx " + taintPath.getArgIndex(idx) + " ==> " + targetExp); // arg idx should be removed if solved
                    solveStack(targetExp, idx, hf, taintPath);
                }
                else {
                    // general cases: propagate the first register
                    // TODO: currently we ignore node that is computed from multiple variable sources, solve if needed
                    Varnode target = node;
                    while(target != null && target.getDef() != null){
                        PcodeOp pcodeOp = target.getDef();
                        RILLog.debugLog(TAG + "try resolve: " + pcodeOp.toString());
                        String mnem = pcodeOp.getMnemonic();
                        switch(mnem){
                            case "CAST":
                            case "COPY":
                            case "INT_SEXT":
                                target = pcodeOp.getInput(0);
                                break;
                            // only consider first register variable
                            case "INT_SUB":
                            case "INT_ADD":
                            case "MULTIEQUAL":
                                int num = pcodeOp.getNumInputs();
                                for(int i=0; i<num; i++){
                                    Varnode inputNode = pcodeOp.getInput(i);
                                    if(!inputNode.isConstant()){
                                        target = inputNode;
                                        break;
                                    }
                                }
                                break;
                            case "CALL":
                                Function func = FunctionUtil.getFunctionWith(program, pcodeOp.getInput(0).getAddress());
                                if(func.toString().equals("operator.new")){ // buffer allocate
                                    RILLog.debugLog(TAG + "buf allocate");
                                }
                                target = null;
                                break;
                            case "LOAD":
                                Varnode input0 = pcodeOp.getInput(0);
                                if(input0.isConstant()){
                                    target = pcodeOp.getInput(1);
                                }else{
                                    target = pcodeOp.getInput(0);
                                }
                                break;
                            default:
                                target = null;
                                RILLog.errorLog(TAG + "unhandled PcodeOp");
                        }
                    }

                    if (target != null) {
                        solveFuncParam(target, idx, hf, taintPath);
                    }
                    else {
                        taintPath.removeArg(idx); // conservatively remove arg if not handled
                        RILLog.errorLog(TAG + "Unhandled Varnode expression: " + exp);
                    }
                }
            }
        }
        else if (node.isUnique()) {
            // Stack variable?
            // If so, trace the stack variable definition
            // iterate all inst in the current function and find the corresponding STORE ins that init the stack variable
            // i.e., LOAD X => find STORE X
            // or LOAD X => X COPY Y

            // TODO unique type can also be a class attribute
            // e.g., PTRADD (register, 0x24) (const, 0x8)
            // Use stack pointer (register, 0x54) to distinguish

            String exp = PCodeUtil.evaluateVarNode(node);
            String targetExp = PCodeUtil.removeLoadPcodeExp(exp);

            if (targetExp.contains(Global.STACK_REG)) {
                RILLog.debugLog(TAG + node.getAddress() + " stack taint propagation: arg idx " + taintPath.getArgIndex(idx) + " ==> " + targetExp); // arg idx should be removed if solved
                solveStack(targetExp, idx, hf, taintPath);
            }
            else {
                // general cases: propagate the first register
                // TODO: currently we ignore node that is computed from multiple variable sources, solve if needed
                Varnode[] nodes = node.getDef().getInputs();
                Varnode target = null;
                for (Varnode vn: nodes) {
                    if (vn.isRegister()) {
                        target = vn; // trace the first register
                        break;
                    }
                }

                if (target != null) {
                    solveFuncParam(target, idx, hf, taintPath);
                }
                else {
                    taintPath.removeArg(idx); // conservatively remove arg if not handled
                    RILLog.errorLog(TAG + "Unhandled Varnode expression: " + exp);
                }
            }
        }
        else {
            // TODO solve memset 42c890 3e9f18
            // TODO solve concat 3d6fb0 3e7624
            // TODO solve value depend on value
            // TODO solve branch
            RILLog.errorLog(TAG + node.getAddress() + " unhandled node type " + node.toString());
            taintPath.removeArg(idx); // conservatively remove arg if not handled
            return;
        }
    }

    /**
     * Solves the function parameter for the given Varnode and updates the taint path with the parameter index.
     *
     * @param node The Varnode representing the function parameter.
     * @param idx The index of the argument in the taint path.
     * @param hf The high-level function in which the taint propagation occurs.
     * @param taintPath The current taint path object to be updated.
     * @return True if the parameter was successfully solved and registered, false otherwise.
     */
    public boolean solveFuncParam(Varnode node, int idx, HighFunction hf, TaintPath taintPath) {
        final String TAG = "[solveFuncParam] ";
        boolean solved = false;
        
        // Retrieve the parameter index for the Varnode
        int paramIdx = PCodeUtil.getNodeParamIndex(node);
        RILLog.debugLog(TAG + "get paramIdx: " + paramIdx);
        
        // Return false if parameter index is invalid
        if(paramIdx < 0 ){
            return solved;
        }
        
        // Update the taint path with the new parameter index
        taintPath.updateArg(idx, paramIdx);
        solved = true;
        RILLog.debugLog(TAG + " register taint propagation: arg idx " + taintPath.getArgIndex(idx) + " ==> " + paramIdx);

        return solved;
    }

    /**
     * Solves the stack variable for the given target expression and updates the taint path with the stack value.
     *
     * @param targetExp The target expression representing the stack variable.
     * @param idx The index of the argument in the taint path.
     * @param hf The high-level function in which the taint propagation occurs.
     * @param taintPath The current taint path object to be updated.
     */
    public void solveStack(String targetExp, int idx, HighFunction hf, TaintPath taintPath) {
        String TAG = "[solveStack] ";
        Varnode srcNode = null;
        boolean changedFlag = false;

        // Check if the target expression matches the expected stack register format
        if (!targetExp.startsWith("PTRSUB " + Global.STACK_REG + " (const, ")) { // TODO: generalize to other ARCHs
            RILLog.errorLog(TAG + "Unhandled stack reg expression " + targetExp);
            taintPath.removeArg(idx);
            taintPath.falseNegative = true;
            return;
        }

        // Extract stack offset from the target expression
        String stack_offset_str = RegexUtil.extractStackOffsetFromExp(targetExp);
        BigInteger offset_big_int = new BigInteger(stack_offset_str.substring(2), 16);
        int stack_offset = offset_big_int.intValue();

        Map<Integer, Byte> stackFrame = new HashMap<>();

        // Recover the whole stack frame
        Iterator<PcodeOpAST> asts = hf.getPcodeOps();
        while (asts.hasNext()) {
            PcodeOpAST ast = asts.next();
            
            // Handle STORE operations
            if (ast.getMnemonic().equals("STORE")) {
                Varnode[] inputs = ast.getInputs();
                Varnode dstNode = inputs[1];
                String dstExp = PCodeUtil.evaluateVarNode(dstNode);

                if (dstNode.getAddress().isStackAddress()) {
                    int size = dstNode.getSize();
                    int offset = (int) dstNode.getOffset();
                    srcNode = ast.getInput(0);
                    if (srcNode.isConstant()) {
                        long val = srcNode.getOffset();
                        // Store bytes into stack frame
                        for (int i = 0; i < size; ++i) {
                            if (!program.getLanguage().isBigEndian()) {
                                // Little endian
                                byte val2Str = (byte) ((val >> (8 * i)) & 0xff);
                                stackFrame.put(offset + i, val2Str);
                            } else {
                                // Big endian
                                RILLog.errorLog("Big endian not solved");
                            }
                        }
                    } else {
                        RILLog.errorLog(TAG + "Stack store expression srcNode is not const");
                    }
                }

            // Handle COPY operations
            } else if (ast.getMnemonic().equals("COPY")) {
                Varnode output = ast.getOutput();
                String dstExp = PCodeUtil.evaluateVarNode(output);
                if (output.getAddress().isStackAddress()) {
                    int size = output.getSize();
                    int offset = (int) output.getOffset();
                    srcNode = ast.getInput(0);
                    if (srcNode.isConstant()) {
                        long val = srcNode.getOffset();
                        // Store bytes into stack frame
                        for (int i = 0; i < size; ++i) {
                            if (!program.getLanguage().isBigEndian()) {
                                // Little endian
                                byte val2Str = (byte) ((val >> (8 * i)) & 0xff);
                                stackFrame.put(offset + i, val2Str);
                            } else {
                                // Big endian
                                RILLog.errorLog("Big endian not solved");
                            }
                        }
                    } else {
                        RILLog.errorLog(TAG + "Stack store expression srcNode is not const");
                    }
                }

            // Handle CALL operations
            } else if (ast.getMnemonic().equals("CALL")) {
                int num = ast.getNumInputs();
                for (int i = 1; i < num; i++) {
                    Varnode inputNode = ast.getInput(i);
                    String inputStr = PCodeUtil.evaluateVarNode(inputNode);
                    if (targetExp.equals(inputStr)) { // Check if the target expression is used as another function parameter
                        changedFlag = true;
                        break;
                    }
                }
            }
        }

        // Obtain value from the stack frame
        int tmp_offset = stack_offset;
        List<Byte> res = new ArrayList<>();
        while (stackFrame.containsKey(tmp_offset)) {
            res.add(stackFrame.get(tmp_offset));
            tmp_offset++;
        }

        // Update taint path based on the recovered stack value
        if (res.size() != 0) {
            RILLog.debugLog(TAG + "stack variable has value");
            taintPath.putResult(idx, res); // Solved
            taintPath.removeArg(idx); // Remove argument since stack variables need to be solved within function
            if (changedFlag) {
                RILLog.debugLog(TAG + "stack variable may be changed");
                taintPath.falseNegative = true;
            } else {
                RILLog.debugLog(TAG + "stack variable successfully solved");
            }
        } else {
            RILLog.errorLog("Stack frame value not found");
            taintPath.removeArg(idx); // Remove argument since stack variables need to be solved within function
            taintPath.falseNegative = true;
        }
    }



    /**
     * Finalizes the taint analysis by logging the taint path, results, and any potential issues.
     *
     * @param taintPath The current taint path object containing the taint analysis data.
     */
    private void taintFinish(TaintPath taintPath) {
        final String TAG = "[taintFinish] ";
        Map<Integer, Long> result = taintPath.getResult();
        Map<Integer, List<Byte>> resultByteArray = taintPath.getResultByteArray();

        // Construct the backward path for debugging
        String backwardPath = "";
        for (int i = 0; i < taintPath.path.size(); i++) {
            Address addr = taintPath.path.get(i);
            backwardPath += addr.toString() + "(" + FunctionUtil.getFunctionWith(program, addr) + ") => ";
        }
        RILLog.debugLog(TAG + "backward path: " + backwardPath);

        // Log each Pcode operation in the trace
        for (int i = 0; i < taintPath.trace.size(); i++) {
            PcodeOp pcodeOp = taintPath.trace.get(i);
            RILLog.debugLog(TAG + "trace: (" + pcodeOp.getSeqnum().getTarget().toString() + ") " + pcodeOp.toString());
        }

        // Continue taint propagation forward
        continueTaintForwad(taintPath);

        // Check for false negatives
        if (taintPath.falseNegative) {
            return;
        }
        if (result.size() != taintPath.taintArgs.size()) {
            return;
        }

        // Log the successfully solved taint path
        RILLog.infoLog(TAG + "Solved taintPath " + taintPath.printPath());

        // Log results
        for (int k : result.keySet()) {
            if (result.get(k) == -1) {
                StringBuilder byteStr = new StringBuilder();
                byteStr.append("[");
                for (int i = 0; i < resultByteArray.get(k).size(); i++) {
                    byteStr.append(String.format("%02x", resultByteArray.get(k).get(i)));
                    if (i != resultByteArray.get(k).size() - 1) {
                        byteStr.append(", ");
                    }
                }
                byteStr.append("]");

                RILLog.infoLog(TAG + "{Key: " + k + ", Value: " + byteStr + "}");
            } else {
                RILLog.infoLog(TAG + "{Key: " + k + ", Value: " + result.get(k) + "}");
            }
        }

        RILLog.infoLog("\n\n");
    }

    /**
     * Continues the taint propagation forward from the last recorded Pcode operation in the trace.
     *
     * @param taintPath The current taint path object containing the taint analysis data.
     */
    private void continueTaintForwad(TaintPath taintPath) {
        String TAG = "[continueTaintForwad] ";
        int size = taintPath.trace.size();
        int idx = size - 1;
        PcodeOp pcodeOp = taintPath.trace.get(idx);
        Varnode node = taintPath.traceNode.get(pcodeOp);
        RILLog.debugLog(TAG + "startPcodeOp: (" + pcodeOp.getSeqnum().getTarget().toString() + ") " + pcodeOp.toString());
        RILLog.debugLog(TAG + "focus node: " + node.toString());
        taintForward(node, pcodeOp, taintPath);
    }

    /**
     * Retrieves exclusive references from a ReferenceIterator, filtering out indirect references and virtual table calls.
     *
     * @param refs The iterator containing references to be processed.
     * @return A list of exclusive references.
     */
    private ArrayList<Reference> getExclusiveRef(ReferenceIterator refs) {
        RILLog.debugLog("[getExclusiveRef]");
        ArrayList<Reference> callRefsList = new ArrayList<>();
        ArrayList<Reference> vRefsList = new ArrayList<>();
        ArrayList<Reference> excluRefsList = new ArrayList<>();

        while (refs.hasNext()) {
            Reference tempRef = refs.next();
            if (!tempRef.isEntryPointReference() && tempRef.getReferenceType().isData()) {
                RILLog.debugLog("[getExclusiveRef] add vref " + tempRef.toString());
                vRefsList.add(tempRef);
            } else if (tempRef.getReferenceType().isIndirect()) {
                RILLog.debugLog("[getExclusiveRef] ignore indirect ref " + tempRef.toString());
            } else {
                RILLog.debugLog("[getExclusiveRef] add callref " + tempRef.toString());
                callRefsList.add(tempRef);
            }
        }

        for (int i = 0; i < vRefsList.size(); i++) {
            Reference vref = vRefsList.get(i);
            Address fromAddr = vref.getFromAddress();
            ReferenceIterator fromRefs = AddressUtil.getReferenceToAddress(program, fromAddr);
            if (fromRefs.hasNext()) { // Virtual Table Call
                Function vFunc = FunctionUtil.getFunctionWith(program, fromRefs.next().getFromAddress());
                if (vFunc == null)
                    continue;
                int j = 0;
                for (; j < callRefsList.size(); j++) {
                    Address callAddr = callRefsList.get(j).getFromAddress();
                    Function callFunc = FunctionUtil.getFunctionWith(program, callAddr);
                    if (vFunc.equals(callFunc)) {
                        break;
                    }
                }
                if (j == callRefsList.size()) {
                    excluRefsList.add(vref);
                }
            } else {
                // To do: handle FDE
            }
        }
        excluRefsList.addAll(callRefsList);
        return excluRefsList;
    }


    private int cmdNum = 0;

    private void outputCmd(String cmd){
        RILLog.infoLog("[Command Result] " + cmd);
        cmdNum += 1;
    }

    /**
     * Generates a JSON object containing the results of taint analysis.
     *
     * @return A JSONObject containing the taint analysis results.
     */
    public JSONObject getJsonResult() {
        jsonResult = new JSONObject();
        int counter = 0;
        for (TaintResult tr : results) {
            jsonResult.put(counter + "", tr.toJsonObj());
            ++counter;
        }
        return jsonResult;
    }




}
