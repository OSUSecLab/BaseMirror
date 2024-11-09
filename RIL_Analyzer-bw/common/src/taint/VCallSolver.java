package taint;

import analyze.Config;
import analyze.Global;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import util.FunctionUtil;
import util.PCodeUtil;
import util.RILLog;
import util.VCallUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * VCallSolver handles the inference of virtual function calls and types
 * by analyzing the pcode operations and related function information.
 */
public class VCallSolver {

    Program program;
    HighFunction hf;
    public Address address;
    public PcodeOpAST pcode;
    public String funcName;
    public String className;
    public String callFuncExp;
    public String baseClassExp;
    public long offset = -1;
    private List<String> cachedFuncs = new ArrayList<>();
    private List<String> typeNameList = new ArrayList<>();
    private List<Function> vFunctions = new ArrayList<>();

    /**
     * Constructor for VCallSolver.
     *
     * @param program The program being analyzed.
     * @param hf The high-level function containing the pcode operation.
     * @param pcode The pcode operation representing the virtual function call.
     */
    public VCallSolver(Program program, HighFunction hf, PcodeOpAST pcode) {
        this.program = program;
        this.hf = hf; // Function containing address/CALLIND
        this.address = pcode.getSeqnum().getTarget(); // Address of CALLIND
        this.pcode = pcode;
        this.funcName = hf.getFunction().getName();
        this.className = hf.getFunction().getParentNamespace().getName();
    }

    public Address getAddress() {
        return address;
    }

    public List<String> getInferredTypeNames() {
        return typeNameList;
    }

    public List<Function> getvFunctions() {
        return vFunctions;
    }

    /**
     * Solves the virtual function call by inferring the base class and function offset.
     */
    public void solve() {
        String TAG = "[solve] ";
        if (className.equals("Global")) {
            RILLog.debugLog(TAG + "ignored non-class methods");
            return;
        }
        PcodeOpAST target = this.pcode;
        RILLog.debugLog(TAG + "target op: " + target.toString() + " at " + this.hf.getFunction().toString());

        // Determine base class expression
        if (target.getNumInputs() < 2) {
            if (className != null) {
                if (hf.getFunction().getParameterCount() < 1) {
                    RILLog.errorLog(TAG + "param count is 0");
                    return;
                }
                Varnode thisNode = hf.getFunction().getParameter(0).getVariableStorage().getFirstVarnode();
                baseClassExp = PCodeUtil.evaluateVarNode(thisNode);
                typeNameList.add(className);
            }
        } else {
            baseClassExp = PCodeUtil.evaluateVarNode(target.getInput(1));
        }

        if (baseClassExp == null) {
            RILLog.errorLog(TAG + "baseClassExp is null");
            return;
        }
        RILLog.debugLog(TAG + "baseClassExp:" + baseClassExp);

        Varnode vCallNode = target.getInput(0);
        if (vCallNode.isConstant()) {
            RILLog.debugLog(TAG + "ignore CALLIND with const func representation");
            return;
        }
        
        // Parse virtual call offset
        callFuncExp = PCodeUtil.evaluateVarNode(vCallNode);
        RILLog.debugLog(TAG + "callFuncExp: " + callFuncExp);
        callFuncExp = callFuncExp.replace(baseClassExp, "@").strip();
        RILLog.debugLog(TAG + "after replace: " + callFuncExp);
        String[] tokens = callFuncExp.split("@");
        if (tokens.length < 2) {
            RILLog.errorLog(TAG + "tokens less than 2");
            return;
        }
        try {
            offset = Long.decode(tokens[1].split(",")[1].strip());
        } catch (Exception e) {
            RILLog.errorLog(TAG + "fail to decode");
            return;
        }
        if (offset == -1) {
            RILLog.errorLog(TAG + "offset is -1");
            return; // cannot resolve virtual call offset
        }
        
        // Infer type from constructor or init functions
        Namespace namespace = (Namespace) hf.getFunction().getParentNamespace();
        Function constructor = FunctionUtil.getFunctionWithName(program, namespace.getName() + "::" + namespace.getName());
        inferTypeFromConstructorOrInit(constructor, offset, 0);
        Function init = FunctionUtil.getFunctionWithName(program, namespace.getName() + "::" + "Init");
        inferTypeFromConstructorOrInit(init, offset, 0);

        // Handle specific corner case for decompiled functions
        if (this.hf.getFunction().toString().equals("IpcModem::DoIoChannelRoutingTx")) {
            solveFinish("IoChannel", offset);
        }
    }

    /**
     * Infers the type from constructor or initialization functions.
     *
     * @param func The function to analyze (constructor or init).
     * @param vtableOffset The offset in the virtual table.
     * @param level The recursion level.
     */
    private void inferTypeFromConstructorOrInit(Function func, long vtableOffset, int level) {
        if (level > Config.MAX_RESURSION) {
            return;
        }
        String TAG = "[inferTypeFromConstructorOrInit] ";
        if (func == null) {
            return;
        }
        DecompileResults dr = Global.getDecompFunc(func);
        HighFunction hf = dr.getHighFunction();
        Iterator<PcodeOpAST> pcodes = hf.getPcodeOps();
        
        // Check if function has parameters
        if (hf.getLocalSymbolMap().getNumParams() == 0) {
            return;
        }
        Varnode thisNode = hf.getLocalSymbolMap().getParamSymbol(0).getStorage().getFirstVarnode();
        String thisNodeStr = PCodeUtil.evaluateVarNode(thisNode);
        
        // Iterate through pcode operations
        while (pcodes.hasNext()) {
            PcodeOpAST pcode = pcodes.next();
            String opStr = pcode.getMnemonic();
            switch (opStr) {
                case "STORE": // Find store operations that assign values
                    Varnode offsetVar = pcode.getInput(1);
                    String offsetStr = PCodeUtil.evaluateVarNode(offsetVar);
                    String classOffsetStr = PCodeUtil.removeLoadPcodeExp(baseClassExp);
                    if (offsetStr.equals(classOffsetStr)) {
                        Varnode value_var = pcode.getInput(2);
                        handleInferFromStore(value_var, func, vtableOffset);
                    } else if (offsetStr.startsWith("PTRADD")) {
                        if (classOffsetStr.startsWith("INT_ADD")) {
                            String tmpClassExp = PCodeUtil.intAdd2ptrAdd(classOffsetStr);
                            if (tmpClassExp.equals(offsetStr)) {
                                Varnode value_var = pcode.getInput(2);
                                handleInferFromStore(value_var, func, vtableOffset);
                            }
                        }
                    }
                    break;
                case "CALL": // Handle function calls that may lead to virtual function resolution
                    if (thisNodeStr.equals(PCodeUtil.evaluateVarNode(pcode.getInput(1)))) {
                        Function calledFunc = FunctionUtil.getFunctionWith(program, pcode.getInput(0).getAddress()).getThunkedFunction(true);
                        if (calledFunc == null) {
                            calledFunc = FunctionUtil.getFunctionWith(program, pcode.getInput(0).getAddress());
                        }
                        if (calledFunc.isExternal()) {
                            break;
                        }
                        inferTypeFromConstructorOrInit(calledFunc, vtableOffset, level + 1);
                    }
                    break;
                default: // Future work: support more pcode operations
                    break;
            }
        }
    }

    /**
     * Handles type inference based on store operations and indirect function calls.
     *
     * @param value_var The value variable involved in the store operation.
     * @param func The function in which the store operation occurs.
     * @param vtableOffset The offset in the virtual table.
     */
    private void handleInferFromStore(Varnode value_var, Function func, long vtableOffset) {
        if (value_var.isConstant()) {
            return;
        } else if (PCodeUtil.evaluateVarNode(value_var).startsWith("CALLIND")) {
            String typeName = "";
            PcodeOp op = value_var.getDef();
            List<PcodeOp> callIndOps = extractUntilOp(op, new ArrayList<>(Arrays.asList("CALLIND")));
            for (PcodeOp callIndOp : callIndOps) {
                callIndOp = callIndOp.getInput(0).getDef(); // Get called function pointer
                if (callIndOp.getMnemonic().equals("LOAD")) { // Function pointer should load from memory
                    callIndOp = callIndOp.getInput(1).getDef(); // Get position op
                    List<PcodeOp> addOps = extractUntilOp(callIndOp, new ArrayList<>(Arrays.asList("INT_ADD", "PTRSUB")));
                    for (PcodeOp addOp : addOps) {
                        value_var = addOp.getInput(1); // Future work: also need to check the first input as base address
                        if (value_var.isConstant()) {
                            long offset = value_var.getOffset();
                            Function indirectFunc = getVFuncWithOffset(FunctionUtil.getFunctionWith(program, this.pcode.getParent().getStart()).getParentNamespace(), offset);
                            // Type name is the return type of this indirect function
                            DecompileResults indDr = Global.getDecompFunc(indirectFunc);
                            HighFunction indHf = indDr.getHighFunction();
                            typeName = indHf.getFunctionPrototype().getReturnType().getName().split(" ")[0];
                            if (typeName.startsWith("undefined")) { // If return type is not clear
                                Iterator<PcodeOpAST> indHfPcodes = indHf.getPcodeOps();
                                while (indHfPcodes.hasNext()) {
                                    PcodeOpAST indHfPcode = indHfPcodes.next();
                                    if (indHfPcode.getMnemonic().equals("RETURN")) { // Find return and corresponding type
                                        List<PcodeOp> callOps = extractUntilOp(indHfPcode, new ArrayList<>(Arrays.asList("CALL")));
                                        for (PcodeOp callOp : callOps) {
                                            Function callee = FunctionUtil.getFunctionWith(program, callOp.getInput(0).getAddress());
                                            if (callee.getName().equals("operator.new")) {
                                                Iterator<PcodeOp> callOpDescs = callOp.getOutput().getDescendants();
                                                while (callOpDescs.hasNext()) {
                                                    PcodeOp callOpDesc = callOpDescs.next();
                                                    List<PcodeOp> descCallOps = reverseExtractUntilOp(callOpDesc, "CALL", indHfPcode);
                                                    for (int j = 0; j < descCallOps.size(); j++) {
                                                        PcodeOp descCallOp = descCallOps.get(j);
                                                        Function descFunc = FunctionUtil.getFunctionWith(program, descCallOp.getInput(0).getAddress()).getThunkedFunction(true);
                                                        if (descFunc.getParentNamespace().getName().equals(descFunc.getName())) { // Constructor function
                                                            typeName = descFunc.getParentNamespace().getName();
                                                            solveFinish(typeName, vtableOffset);
                                                        }
                                                    }
                                                }
                                            } else {
                                                assert false : "New case for MULTIEQUAL call";
                                            }
                                        }
                                    }
                                }
                            } else {
                                solveFinish(typeName, vtableOffset);
                            }
                        }
                    }
                } else {
                    assert false : "New Function pointer case";
                }
            }
        } else if (value_var.isRegister()) {
            for (Parameter param : func.getParameters()) {
                Varnode paramNode = param.getVariableStorage().getFirstVarnode();
                // Parameter match
                if (paramNode.toString().equals(PCodeUtil.evaluateVarNode(value_var))) {
                    DataType type = param.getDataType();
                    String typeName = type.getName().replace("*", "").strip();
                    solveFinish(typeName, vtableOffset);
                    return;
                }
            }
        }
    }

    /**
     * Finalizes the inference process by caching the results and resolving virtual functions.
     *
     * @param typeName The inferred type name.
     * @param vtableOffset The offset in the virtual table.
     */
    private void solveFinish(String typeName, long vtableOffset) {
        String TAG = "solveFinish";
        VCallUtil.addVType(className, baseClassExp, typeName); // Cache solved results
        // Resolve virtual function from virtual function table
        Function constructor = FunctionUtil.getFunctionWithName(program, typeName + "::" + typeName);
        if (constructor == null) {
            return;
        }
        Namespace namespace = constructor.getParentNamespace();
        if (namespace == null) {
            return;
        }
        Function vFunction = getVFuncWithOffset(namespace, vtableOffset);
        if (vFunction != null) {
            vFunctions.add(vFunction);
            RILLog.debugLog(TAG + "vFunction:" + vFunction.toString() + " at " + this.hf.getFunction().toString());
        }
    }

    /**
     * Extracts a list of pcode operations in reverse order until a specific mnemonic is encountered.
     *
     * @param op The starting pcode operation.
     * @param mnem The mnemonic to search for.
     * @param filterOp The pcode operation used as a filter.
     * @return A list of pcode operations.
     */
    private List<PcodeOp> reverseExtractUntilOp(PcodeOp op, String mnem, PcodeOp filterOp) {
        boolean extract = true;
        List<PcodeOp> returnOps = new ArrayList<>();
        String opMnem = op.getMnemonic();
        switch (opMnem) {
            case "CAST":
                Iterator<PcodeOp> descs = op.getOutput().getDescendants();
                while (descs.hasNext()) {
                    PcodeOp desc = descs.next();
                    if (desc.equals(filterOp)) {
                        continue;
                    }
                    List<PcodeOp> tmp = reverseExtractUntilOp(desc, mnem, filterOp);
                    returnOps.addAll(tmp);
                }
                break;
            default:
                if (opMnem.equals(mnem)) {
                    returnOps.add(op);
                }
                break;
        }
        return returnOps;
    }

    /**
     * Extracts a list of pcode operations until a specific mnemonic is encountered.
     *
     * @param op The starting pcode operation.
     * @param mnems A list of mnemonics to search for.
     * @return A list of pcode operations.
     */
    private List<PcodeOp> extractUntilOp(PcodeOp op, List<String> mnems) {
        boolean extract = true;
        List<PcodeOp> retPcodeOps = new ArrayList<>();
        String opMnem = op.getMnemonic();
        switch (opMnem) {
            case "COPY":
            case "CAST":
            case "PTRADD": {
                PcodeOp tmpOp = op.getInput(0).getDef();
                List<PcodeOp> tmpOps = extractUntilOp(tmpOp, mnems);
                retPcodeOps.addAll(tmpOps);
                }
                break;
            case "RETURN": {
                if (op.getInput(1) != null) {
                    PcodeOp tmpOp = op.getInput(1).getDef();
                    List<PcodeOp> tmpOps = extractUntilOp(tmpOp, mnems);
                    retPcodeOps.addAll(tmpOps);
                }
                }
                break;
            case "MULTIEQUAL": {
                for (int i = 0; i < op.getNumInputs(); i++) {
                    PcodeOp tmpOp = op.getInput(i).getDef();
                    List<PcodeOp> tmpOps = extractUntilOp(tmpOp, mnems);
                    retPcodeOps.addAll(tmpOps);
                }
                }
                break;
            default:
                if (mnems.contains(opMnem)) {
                    retPcodeOps.add(op);
                } else {
                    assert false : "new case in extractUntilOp";
                }
                break;
        }
        return retPcodeOps;
    }

    /**
     * Retrieves a virtual function with a given offset from the virtual function table.
     *
     * @param namespace The namespace to search in.
     * @param offset The offset in the virtual table.
     * @return The resolved function, or null if not found.
     */
    public Function getVFuncWithOffset(Namespace namespace, long offset) {
        String TAG = "[getVFuncWithOffset] ";
        Symbol symbol = null;
        if (VCallUtil.containVTable(namespace.getName())) {
            symbol = VCallUtil.getVTable(namespace.getName());
        } else {
            SymbolTable symtab = program.getSymbolTable();
            SymbolIterator symbols = symtab.getSymbols(namespace);
            while (symbols.hasNext()) {
                symbol = symbols.next();
                if (symbol.getName().equals("vtable")) {
                    VCallUtil.addVTable(namespace.getName(), symbol);
                    break;
                }
            }
        }

        Address addr = symbol.getAddress().add(Global.POINTER_SIZE * 2 + offset);
        Data data = program.getListing().getDataAt(addr);
        if (data == null) {
            RILLog.debugLog(TAG + "data at " + addr.toString() + " is null");
        } else {
            try {
                Address dataAddr = (Address) data.getValue();
                Function func = FunctionUtil.getFunctionWith(program, dataAddr);
                return func;
            } catch (ClassCastException e) {
                RILLog.debugLog(TAG + "fail to decode data value in the vtable of " + namespace.getName());
            }
        }
        return null;
    }
}
