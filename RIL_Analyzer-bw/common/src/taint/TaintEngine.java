package taint;

import analyze.Config;
import analyze.Constants;
import analyze.Global;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import org.json.JSONObject;
import util.*;
import util.FunctionUtil;
import util.PCodeUtil;
import util.RILLog;
import util.RegexUtil;

import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.util.*;


public class TaintEngine {

    Address start; // Starting address for taint analysis.
    List<TaintSource> taintSources; // List of taint sources.
    String taintExpression; // Expression used to determine taint.
    List<TaintPath> paths; // List of taint paths generated during analysis.
    HashMap<Address, String> inputLocations; // Map of addresses to input locations.
    public JSONObject jsonResult = new JSONObject(); // JSON object to store results.
    public String outputStr = ""; // String to store output results.
    CmdChannel cmdChannel; // Command channel for processing.

    Program program; // Program context for analysis.

    ArrayList<Address> exportedFuncs = new ArrayList<Address>(); // List of exported function addresses.
    List<TaintResult> results = new ArrayList<>(); // List of taint analysis results.


    // Constructor initializing TaintEngine with start address and taint expression.
    public TaintEngine(Address startAdd, String taintExp) {
        start = startAdd;
        taintExpression = taintExp;
        paths = new ArrayList<>();
        inputLocations = new HashMap<>();
        program = Global.getProgram(); // Get the current program context.

        if(Config.CHECK_FD){
            RILLog.initLog("CmdChannel"); // Initialize logging for CmdChannel.
            cmdChannel = new CmdChannel(); // Create a new CmdChannel instance.
        }
    }

    // Default constructor for TaintEngine.
    public TaintEngine() {
        program = Global.getProgram(); // Get the current program context.
        if(Config.CHECK_FD){
            RILLog.initLog("CmdChannel"); // Initialize logging for CmdChannel.
            cmdChannel = new CmdChannel(); // Create a new CmdChannel instance.
        }
    }

    // Starts the backward taint analysis process for a list of taint sources.
    public void startBackwardTaint(List<TaintSource> taintSources) throws FileNotFoundException {
        String TAG = "[startBackwardTaint] ";
        for (TaintSource ts: taintSources) {
            if(ts.address == null){
                RILLog.initLog("LOG.txt." + ts.getName());
                RILLog.debugLog(TAG + "ts.address is null");
                continue; // Skip taint source if address is null.
            }
            RILLog.initLog("LOG.txt." + ts.getName() + "." + ts.address.toString());

            Address startAddress = ts.address; // Get the start address from the taint source.
            RILLog.debugLog(TAG + "handling address: " + startAddress.toString());

            TaintPath tp = new TaintPath(ts.fd_arg, FunctionUtil.getFunctionWith(program, startAddress), ts.args);
            tp.addToPath(startAddress); // Add the start address to the taint path.

            // Begin analysis of function calls.
            interFunctionCallJump(startAddress, tp, 0);
            RILLog.debugLog(TAG + "Finish taint analysis");
            // Revert stdout to default.
            System.setOut(System.out);
        }
    }

    // Handles jumps between functions during backward taint analysis.
    private void interFunctionCallJump(Address start, TaintPath taintPath, int level) {
        final String TAG = "[interFunctionJump] ";

        if (level >= Config.MAX_FUNCTION_JUMP) {
            RILLog.errorLog(TAG + " exceeding max function jump limit, exiting");
            return; // Prevent stack overflow by stopping further jumps.
        }

        List<Address> toBeTainted = new ArrayList<>(); // List of addresses to be tainted.

        // Get references to the start address.
        ReferenceIterator rawRefs = AddressUtil.getReferenceToAddress(program, start);
        ArrayList<Reference> refs = getExclusiveRef(rawRefs);
        RILLog.debugLog(TAG + "Handling ref to " + start);
        for (Reference curRef : refs) {
            Address curRefAddr = curRef.getFromAddress(); // Get the address of the reference.
            if (curRef.isEntryPointReference()) {
                RILLog.debugLog(TAG + curRefAddr + " ref is an Entry Point");
                continue; // Skip entry point references.
            } else if (curRef.getReferenceType().isData()) {
                RILLog.debugLog(TAG + curRefAddr + " ref is Data(Virtual Table)");
                // Handle virtual table references.
                handleVTableRef(curRefAddr, toBeTainted);
                continue;
            } else if (curRef.getReferenceType().isIndirect()) {
                RILLog.debugLog(TAG + curRefAddr + " ref is Indirect(Virtual Table)");
                continue; // Handle indirect references.
            } else {
                toBeTainted.add(curRefAddr); // Add the address to the list of addresses to be tainted.
            }
        }

        if (VCallUtil.vCalls.keySet().contains(start)) {
            // Add virtual function callers to the list.
            List<Address> vCallSites = VCallUtil.vCalls.get(start);
            for (Address vCallAddress : vCallSites) {
                toBeTainted.add(vCallAddress);
                RILLog.debugLog(TAG + String.format("adding virtual call 0X%x ==> 0X%x", start.getUnsignedOffset(), vCallAddress.getUnsignedOffset()));
            }
        }

        RILLog.debugLog("\n\n");

        // Continue taint analysis for each address in the list.
        for (Address addr : toBeTainted) {
            if (taintPath.containsPath(addr))
                continue; // Skip if the address is already in the path.
            intraFunctionBackwardTaint(addr, taintPath.clone(), level); // Perform intra-function backward taint analysis.
        }
    }

    // Handles virtual table references.
    private void handleVTableRef(Address addr, List<Address> toBeTainted) {
        String TAG = "[handleVTableRef] ";
        RILLog.debugLog(TAG + "reserved");
        assert 0 > 1; // Reserved for future implementation or debugging purposes.
    }

    // Performs backward taint analysis within a single function.
    public void intraFunctionBackwardTaint(Address start, TaintPath taintPath, int level) {
        final String TAG = "[intraFunctionBackwardTaint] ";
        List<Integer> argIndex = new ArrayList<>(taintPath.taintArgs); // List of argument indices to be tainted.

        if (start == null) {
            RILLog.errorLog(TAG + " Start address is null");
            return; // Exit if the start address is null.
        }

        Function func = FunctionUtil.getFunctionWith(program, start); // Get the function at the start address.
        if (func == null) {
            RILLog.errorLog(TAG + " function at " + start + " is null");
            return; // Exit if the function is null.
        }

        // Skip functions in the blacklist to avoid branch explosion.
        for (String blFunc : Constants.funcBlackList) {
            if (func.getName().contains(blFunc)) return;
        }

        RILLog.debugLog(TAG + " at function " + func.getName() + " entry point " + start);
        HighFunction hf = Global.getDecompFunc(func).getHighFunction(); // Get the high-level function representation.

        // Identify the pcode instruction of the taint starting point.
        Iterator<PcodeOpAST> startPcodeOpAST = hf.getPcodeOps(start);
        PcodeOp startPcodeOp = null;
        if (startPcodeOpAST.hasNext()) {
            startPcodeOp = startPcodeOpAST.next();
            RILLog.debugLog(TAG + "find startPcodeOp by addr: " + startPcodeOp.toString());
        } else {
            startPcodeOpAST = hf.getPcodeOps(); // If address-specific search fails, search all pcode ops.
            while (startPcodeOpAST.hasNext()) {
                startPcodeOp = startPcodeOpAST.next();
                if (startPcodeOp.getMnemonic() == "CALL") {
                    RILLog.debugLog(TAG + "find startPcodeOp: " + startPcodeOp.toString());
                    break;
                }
            }
        }

        if (startPcodeOp == null) {
            RILLog.errorLog(TAG + start + " has no pcodeopast");
            return; // Exit if no pcode operation is found.
        }
        RILLog.debugLog(TAG + "pcodeOp has inputs number " + startPcodeOp.getNumInputs());
        for (int idx : argIndex) {
            if (startPcodeOp.getNumInputs() < idx + 1) {
                RILLog.debugLog(TAG + "Not enough inputs for taint propagation");
                return; // Exit if the number of inputs is insufficient.
            }
        }

        // Extract taint arguments as variable nodes and add them to the path.
        taintPath.addToTrace(startPcodeOp);
        taintPath.addToPath(start);

        // Verify file descriptors if required.
        if (Config.CHECK_FD) {
            if (!cmdChannel.verifyFd(hf, startPcodeOp, taintPath)) {
                return; // Exit if file descriptor verification fails.
            }
        }

        // Start backward taint analysis on variable nodes.
        for (int idx : argIndex) {
            Varnode node = startPcodeOp.getInput(idx + 1); // Get the variable node at the index.

            // Recursively perform backward taint analysis on the variable node.
            taintSingleStep(hf, node, idx, taintPath);
        }

        RILLog.debugLog(taintPath.printPath() + "\n" + taintPath.printTrace() + "\n");

        // Check if taint analysis is complete.
        if (taintPath.getTaintArgNum() == 0) {
            taintFinish(taintPath); // Finish the taint analysis if no more arguments are tainted.
        } else {
            // Continue to analyze the function callers.
            interFunctionCallJump(func.getEntryPoint(), taintPath, level + 1);
        }
    }

    // Performs single-step taint analysis on a variable node.
    private void taintSingleStep(HighFunction hf, Varnode node, int idx, TaintPath taintPath) {
        final String TAG = "[taintSingleStep] ";

        if (node == null) {
            RILLog.errorLog(TAG + " VarNode is null");
            return; // Exit if the variable node is null.
        }

        if (node.isConstant()) {
            // Handle constant nodes by solving their values directly.
            long val = node.getAddress().getUnsignedOffset();
            taintPath.putResult(idx, val);
            taintPath.removeArg(idx);
            RILLog.debugLog(TAG + node.getAddress() + " constant taint propagation: arg idx " + idx + " ==> " + val);
        } else if (node.isRegister()) {
            // Handle register nodes by tracing them in the function caller.
            boolean solved = solveFuncParam(node, idx, hf, taintPath);

            if (!solved) {
                // Handle intermediate registers by solving them as stack registers.
                String exp = PCodeUtil.evaluateVarNode(node);
                String targetExp = PCodeUtil.removeLoadPcodeExp(exp);

                if (targetExp.contains(Global.STACK_REG)) {
                    RILLog.debugLog(TAG + node.getAddress() + " stack taint propagation: arg idx " + idx + " ==> " + targetExp);
                    solveStack(targetExp, idx, hf, taintPath);
                } else {
                    // General case: propagate the first register found in the definition.
                    PcodeOp pcodeOp = node.getDef();
                    Varnode target = null;
                    if (pcodeOp != null) {
                        Varnode[] nodes = pcodeOp.getInputs();
                        for (Varnode vn : nodes) {
                            if (vn.isRegister()) {
                                target = vn; // Trace the first register.
                                break;
                            }
                        }
                    } else {
                        RILLog.debugLog(TAG + "no def");
                    }

                    if (target != null) {
                        solveFuncParam(target, idx, hf, taintPath);
                    } else {
                        taintPath.removeArg(idx); // Remove argument if not handled.
                        RILLog.errorLog(TAG + "Unhandled Varnode expression: " + exp);
                    }
                }
            }
        } else if (node.isUnique()) {
            // Handle unique nodes (e.g., stack variables) by tracing their definitions.
            String exp = PCodeUtil.evaluateVarNode(node);
            String targetExp = PCodeUtil.removeLoadPcodeExp(exp);

            if (targetExp.contains(Global.STACK_REG)) {
                RILLog.debugLog(TAG + node.getAddress() + " stack taint propagation: arg idx " + idx + " ==> " + targetExp);
                solveStack(targetExp, idx, hf, taintPath);
            } else {
                // General case: propagate the first register found in the definition.
                Varnode[] nodes = node.getDef().getInputs();
                Varnode target = null;
                for (Varnode vn : nodes) {
                    if (vn.isRegister()) {
                        target = vn; // Trace the first register.
                        break;
                    }
                }

                if (target != null) {
                    solveFuncParam(target, idx, hf, taintPath);
                } else {
                    taintPath.removeArg(idx); // Remove argument if not handled.
                    RILLog.errorLog(TAG + "Unhandled Varnode expression: " + exp);
                }
            }
        } else {
            // Handle unhandled node types.
            RILLog.errorLog(TAG + node.getAddress() + " unhandled node type " + node.toString());
            taintPath.removeArg(idx); // Remove argument if not handled.
            return;
        }
    }


    public boolean solveFuncParam(Varnode node, int idx, HighFunction hf, TaintPath taintPath) {
        final String TAG = "[solveFuncParam] ";
        boolean solved = false;
        int paramIdx = PCodeUtil.getNodeParamIndex(node);
        RILLog.debugLog(TAG + "get paramIdx: " + paramIdx);
        if (paramIdx < 0) {
            return solved;
        }
        taintPath.removeArg(idx);
        taintPath.addArgIndex(paramIdx);
        solved = true;
        RILLog.debugLog(TAG + " register taint propagation: arg idx " + idx + " ==> " + paramIdx);

        return solved;
    }

    public void solveStack(String targetExp, int idx, HighFunction hf, TaintPath taintPath) {
        // handle stack variable
        String TAG = "[solveStack] ";
        Varnode srcNode = null;

        if (!targetExp.startsWith("PTRSUB " + Global.STACK_REG + " (const, ")) { // TODO: generalize to other ARCHs
            RILLog.errorLog(TAG + "Unhandled stack reg expression " + targetExp);
            taintPath.removeArg(idx);
            return;
        }

        String stack_offset_str = RegexUtil.extractStackOffsetFromExp(targetExp);
        BigInteger offset_big_int = new BigInteger(stack_offset_str.substring(2), 16);
        int stack_offset = offset_big_int.intValue();

        Map<Integer, Byte> stackFrame = new HashMap<>();
        Map<Integer, Integer> stackFlag = new HashMap<>();
        // Recover the whole stack frame
        Iterator<PcodeOpAST> asts = hf.getPcodeOps();
        while (asts.hasNext()) {
            PcodeOpAST ast = asts.next();
            if (ast.getMnemonic().equals("STORE")) {
                Varnode[] inputs = ast.getInputs();
                Varnode dstNode = inputs[1];
                String dstExp = PCodeUtil.evaluateVarNode(dstNode);
                if (dstNode.getAddress().isStackAddress()) {
                    int size = dstNode.getSize();
                    int offset = (int) dstNode.getOffset();
                    srcNode = ast.getInput(0);
                    put2Stack(srcNode, stackFrame, stackFlag, offset, 0);
                }
            } else if (ast.getMnemonic().equals("COPY")) { // Step 1: check if the expressions match
                Varnode output = ast.getOutput();
                String dstExp = PCodeUtil.evaluateVarNode(output);
                if (output.getAddress().isStackAddress()) {
                    int size = output.getSize();
                    int offset = (int) output.getOffset();
                    srcNode = ast.getInput(0);
                    put2Stack(srcNode, stackFrame, stackFlag, offset, 0);
                }
            } else if (ast.getMnemonic().equals("PIECE")) { // concat-likely functions
                Varnode outputNode = ast.getOutput();
                String outputNodeStr = outputNode.toString();
                if (outputNodeStr.startsWith("(stack")) { // make sure stack var
                    String cur_offset_str = outputNodeStr.split(",")[1].trim();
                    if (stack_offset_str.equals(cur_offset_str)) {
                        int offsetIdx = 0;
                        int offset = (int) outputNode.getOffset();
                        Varnode inputNode2 = ast.getInput(1);
                        offsetIdx = put2Stack(inputNode2, stackFrame, stackFlag, offset, offsetIdx);
                        Varnode inputNode1 = ast.getInput(0);
                        put2Stack(inputNode1, stackFrame, stackFlag, offset, offsetIdx);
                    }
                }
            }
        }

        // obtain value from stack frame
        int tmp_offset = stack_offset;
        List<Byte> res = new ArrayList<>();
        List<Integer> resFlag = new ArrayList<>();
        while (stackFrame.containsKey(tmp_offset)) {
            res.add(stackFrame.get(tmp_offset));
            resFlag.add(stackFlag.get(tmp_offset));
            tmp_offset++;
        }

        if (res.size() != 0) {
            RILLog.debugLog(TAG + "stack variable successfully solved");
            taintPath.putResult(idx, res, resFlag); // solved
        } else {
            RILLog.errorLog("Stack frame value not found");
        }

        taintPath.removeArg(idx); // remove arg regardless of solved or not, since stack variables need to be solved within function
    }

    private int put2Stack(Varnode node, Map<Integer, Byte> stackFrame, Map<Integer, Integer> stackFlag, int offset, int idx) {
        long value = 0;
        int staticFlag = 0; // 0 for param(dynamic) and 1 for const(static)
        if (node.isConstant()) {
            value = node.getOffset();
            staticFlag = 1;
        }
        // store bytes into stack frame
        for (int j = 0; j < node.getSize(); ++j) {
            if (!program.getLanguage().isBigEndian()) {
                // little endian
                byte val2Str = (byte) ((value >> (8 * j)) & 0xff);
                stackFrame.put(offset + idx, val2Str);
                stackFlag.put(offset + idx, staticFlag);
                idx++;
            } else {
                // big endian
                RILLog.errorLog("Big endian not solved");
            }
        }
        return idx;
    }

    private void taintFinish(TaintPath taintPath) {
        final String TAG = "[taintFinish] ";
        RILLog.infoLog(TAG + "Solved taintPath " + taintPath.printPath());
        Map<Integer, Long> result = taintPath.getResult();
        Map<Integer, List<Byte>> resultByteArray = taintPath.getResultByteArray();
        Map<Integer, List<Integer>> resultFlag = taintPath.getResultFlag();

        if (result.size() != 0) {
            for (int k : result.keySet()) {
                RILLog.infoLog(TAG + "{Key: " + k + ", Value: " + result.get(k) + "}");
            }
        } else if (resultByteArray.size() != 0) {
            for (int k : resultByteArray.keySet()) {
                StringBuilder byteStr = new StringBuilder();
                StringBuilder flagStr = new StringBuilder();
                byteStr.append("[");
                flagStr.append("[");
                for (int i = 0; i < resultByteArray.get(k).size(); i++) {
                    byteStr.append(String.format("%02x", resultByteArray.get(k).get(i)));
                    flagStr.append(String.format("%02x", resultFlag.get(k).get(i)));
                    if (i != resultByteArray.get(k).size() - 1) {
                        byteStr.append(", ");
                        flagStr.append(", ");
                    }
                }
                byteStr.append("]");
                flagStr.append("]");

                RILLog.infoLog(TAG + "{       Key: " + k + ", Value: " + byteStr + "}");
                RILLog.infoLog(TAG + "{StaticFlag: " + k + ", Value: " + flagStr + "}");
            }
        } else {
            RILLog.infoLog(TAG + "{Hybrid Command}");
        }

        RILLog.infoLog("\n\n");
    }

    /**
     * Retrieves a list of exclusive references that are not shared with any call references.
     * 
     * @param refs An iterator over all references.
     * @return A list of exclusive references that are either virtual table calls or not associated with any call reference.
     */
    private ArrayList<Reference> getExclusiveRef(ReferenceIterator refs) {
        RILLog.debugLog("[getExclusiveRef]");
        ArrayList<Reference> callRefsList = new ArrayList<Reference>(); // List to hold call references
        ArrayList<Reference> vRefsList = new ArrayList<Reference>(); // List to hold virtual table references
        ArrayList<Reference> excluRefsList = new ArrayList<Reference>(); // List to hold exclusive references

        // Iterate over all references
        while (refs.hasNext()) {
            Reference tempRef = refs.next();
            if (!tempRef.isEntryPointReference() && tempRef.getReferenceType().isData()) {
                // Add to virtual table references if it's a data reference and not an entry point
                RILLog.debugLog("[getExclusiveRef] add vref " + tempRef.toString());
                vRefsList.add(tempRef);
            } else if (tempRef.getReferenceType().isIndirect()) {
                // Ignore indirect references
                RILLog.debugLog("[getExclusiveRef] ignore indirect ref " + tempRef.toString());
                // Address refAddr = tempRef.getFromAddress(); // Optionally handle exception conditions
            } else {
                // Add to call references
                RILLog.debugLog("[getExclusiveRef] add callref " + tempRef.toString());
                callRefsList.add(tempRef);
            }
        }

        // Check virtual table references against call references
        for (int i = 0; i < vRefsList.size(); i++) {
            Reference vref = vRefsList.get(i);
            Address fromAddr = vref.getFromAddress();
            ReferenceIterator fromRefs = AddressUtil.getReferenceToAddress(program, fromAddr);

            if (fromRefs.hasNext()) { // Virtual Table Call detected
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

                // If no matching call function is found, add to exclusive references
                if (j == callRefsList.size()) {
                    excluRefsList.add(vref);
                }
            } else {
                // To do: handle FDE (Frame Description Entry) references if needed
                // excluRefsList.add(vref); // Optionally add FDE references
            }
        }

        // Add all call references to the list of exclusive references
        excluRefsList.addAll(callRefsList);
        return excluRefsList;
    }

    private int cmdNum = 0; // Counter for commands

    /**
     * Logs the result of a command and increments the command counter.
     * 
     * @param cmd The command result to be logged.
     */
    private void outputCmd(String cmd) {
        RILLog.infoLog("[Command Result] " + cmd);
        cmdNum += 1;
    }

    /**
     * Converts the results of taint analysis into a JSON object.
     * 
     * @return A JSON object containing the taint analysis results.
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
