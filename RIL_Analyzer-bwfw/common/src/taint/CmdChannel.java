package taint;

import analyze.Constants;
import analyze.Global;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.string.FoundString;
import util.*;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class CmdChannel {
    // List to store binary strings found in the binary
    public ArrayList<BinaryString> binaryStrings;
    
    // Stack to store Pcode operations for function calls
    private ArrayList<PcodeOp> callStack = new ArrayList<PcodeOp>();

    // Current program being analyzed
    private Program program;

    // Constructor for CmdChannel
    public CmdChannel(){
        String TAG = "[CmdChannel] ";
        program = Global.getProgram();
        binaryStrings = new ArrayList<BinaryString>();
        
        // Initialize FlatProgramAPI for finding strings in the binary
        FlatProgramAPI fpa = new FlatProgramAPI(program);
        
        // Find all strings in the binary with a minimum length of 4
        List<FoundString> strList = fpa.findStrings(null, 4, 1, true, true);
        for(FoundString str: strList){
            // Check if the found string is a valid path
            if(SymbolUtil.isValidPath(str.getString(program.getMemory()))){
                Address strAddr = str.getAddress();
                RILLog.debugLog(TAG + str + "at loc: " + strAddr.toString());
                BinaryString binaryString = new BinaryString(str.getString(program.getMemory()), strAddr);

                // Process references to the valid path string
                ArrayList<Function> walkedFuncs = new ArrayList<Function>(); // Avoid processing the same function multiple times
                ReferenceIterator refs = program.getReferenceManager().getReferencesTo(strAddr);
                while(refs.hasNext()){
                    // Get Reference to valid paths
                    Reference curRef = refs.next();
                    Address fromAddr = curRef.getFromAddress();
                    Function func = FunctionUtil.getFunctionWith(program, fromAddr);
                    
                    // Find operations related to the path string in the function
                    if(func != null){
                        findOpen(func, fromAddr, binaryString);
                    }
                }
            }
        }
    }

    // Method to find operations that use the path string in a function
    private void findOpen(Function func, Address fromAddr, BinaryString binaryString){
        String TAG = "[findOpen] ";
        RILLog.debugLog(TAG + "find " + binaryString.getStr() + " at " + binaryString.getAddress().toString() + " used in the Function " + func.toString());

        // Get high-level function representation
        HighFunction hf = Global.getDecompFunc(func).getHighFunction();
        Iterator<PcodeOpAST> pcodes = hf.getPcodeOps(fromAddr);
        while(pcodes.hasNext()){
            PcodeOp inst = pcodes.next();
            String instStr = inst.toString();
            
            // Check if the PcodeOp contains the path string address
            if(instStr.contains("0x" + binaryString.getAddress().toString().replaceFirst("^0+(?!$)", ""))){
                RILLog.debugLog(TAG + " find real user inst: " + instStr);

                // Forward analysis based on the mnemonic of the PcodeOp
                String mnemonic = inst.getMnemonic();
                switch (mnemonic){
                    case "COPY": // Handle COPY operations
                        handleValueCOPY(func, inst, binaryString);
                        return;
                    case "CALL": // Handle CALL operations
                        handleCALL(inst, binaryString, null);
                        return;
                    default:
                        // TODO: Handle other unseen cases
                        RILLog.errorLog(TAG + "unseen mnemonic referring to string addr");
                        assert 0 > 1;
                        return;
                }
            }
        }
    }

    // Method to taint and analyze operations that use the specified node in a function
    private void taintToOpen(Function func, Varnode node, BinaryString binaryString){
        String TAG = "[taintToOpen] ";
        RILLog.debugLog(TAG + "handle " + node.toString() + " in the Function " + func.toString());

        // Ignore destructors
        if(func.toString().contains("::~")){
            RILLog.debugLog(TAG + "deconstructor and ignored");
            return;
        }
        
        // Process all descendant nodes
        Iterator<PcodeOp> pcodes = node.getDescendants();
        while(pcodes.hasNext()){
            PcodeOp inst = pcodes.next();
            RILLog.debugLog(TAG + "find user inst: " + inst.toString());
            handleNodeUser(func, inst, node, binaryString);
        }
    }

    // Handle PcodeOp instructions that use a specific node
    private void handleNodeUser(Function func, PcodeOp inst, Varnode node, BinaryString binaryString){
        String TAG = "[handleNodeUser] ";
        String mnemonic = inst.getMnemonic();
        switch (mnemonic){
            case "COPY":
            case "INT_ZEXT":
            case "CAST":
            case "PIECE":
                handleValueCOPY(func, inst, binaryString);
                break;
            case "CALL":
                handleCALL(inst, binaryString, node);
                break;
            case "STORE": // Handle STORE operations
                // TODO: Handle storage to global variables or class members
                handleStore(func, inst, binaryString);
                break;
            case "INT_NOTEQUAL":
                // Ignore operations comparing addresses
                RILLog.debugLog(TAG + "ignored op");
                break;
            default:
                // TODO: Handle other unseen cases
                RILLog.debugLog(TAG + "unseen mnemonic referring to string addr");
                assert 0 > 1;
        }
    }

    // Handle functions where the binary string is passed as a parameter
    private void taintToOpenByCall(Function func, int paramIdx, BinaryString binaryString){
        String TAG = "[taintToOpenByCall] ";
        RILLog.debugLog(TAG + "handle " + func.toString() + " with param " + paramIdx);
        
        // Ignore external functions
        if(func.isExternal()){
            RILLog.debugLog(TAG + "ignored external function called");
            return;
        }
        
        Varnode node = getFuncParamNode(func, paramIdx - 1);
        if(node != null) {
            taintToOpen(func, node, binaryString);
        }else{
            RILLog.debugLog(TAG + "fail to get param node and ignored");
        }
    }

    // Get the function parameter node based on the index
    private Varnode getFuncParamNode(Function func, int paramIdx){
        String TAG = "[getFuncParamNode] ";
        HighFunction hf = Global.getDecompFunc(func).getHighFunction();
        LocalSymbolMap localSymbolMap = hf.getLocalSymbolMap();
        try{
            HighSymbol highSymbol = localSymbolMap.getParamSymbol(paramIdx);
            HighVariable highVariable = highSymbol.getHighVariable();
            Varnode node = highVariable.getRepresentative();
            RILLog.debugLog(TAG + node.toString() + ":" + node.getHigh().getName());
            return node;
        }catch (ArrayIndexOutOfBoundsException e){
            RILLog.debugLog(TAG + func.toString() + " prototype only has " + localSymbolMap.getNumParams() + " params");
            return null;
        }
    }

    // Check if a function is a format function
    private boolean isFormatFunc(Function func){
        return Constants.FormatFuncs.contains(func.toString());
    }

    // Check if a function is an open function
    private boolean isOpenFunc(Function func){
        return Constants.OpenFuncs.contains(func.toString());
    }

    // Handle COPY operations by analyzing the output node
    private void handleValueCOPY(Function func, PcodeOp inst, BinaryString binaryString){
        String TAG = "[handleValueCOPY] ";
        Varnode outputNode = inst.getOutput();
        RILLog.debugLog(TAG + outputNode.toString());
        taintToOpen(func, outputNode, binaryString);
    }

    private void handleCALL(PcodeOp inst, BinaryString binaryString, Varnode node){
        String TAG = "[handleCALL] ";
        RILLog.debugLog(TAG + "inst: " + inst.toString());

        // Add the current CALL instruction to the call stack
        callStack.add(inst);

        // Retrieve the address of the called function from the CALL instruction
        Varnode calledFuncNode = inst.getInput(0);
        Address calledFuncAddr = calledFuncNode.getAddress();
        Function calledFunc = FunctionUtil.getFunctionWith(program, calledFuncAddr);

        // Check if the called function is an open function
        if(isOpenFunc(calledFunc)){
            binaryString.add2OpenOp(inst);
        } else if(isFormatFunc(calledFunc)){
            RILLog.debugLog(TAG + "reach format func");

            // Log the function that called the format function
            RILLog.debugLog(TAG + "callerFunc: " + calledFunc.toString());

            // Check the grandparent instruction in the call stack
            PcodeOp grandParentInst = callStack.get(callStack.size() - 2);
            RILLog.debugLog(TAG + "back to grandParent: " + grandParentInst.toString());

            // Remove the current and previous instructions from the call stack
            callStack.remove(callStack.size() - 1);
            callStack.remove(callStack.size() - 1);

            // Assume that an open will occur immediately after a format function
            Varnode strNodeRep = grandParentInst.getInput(1);
            PcodeBlockBasic pcodeBlockBasic = grandParentInst.getParent();
            Iterator<PcodeOp> pcodeOpIterator = pcodeBlockBasic.getIterator();

            while(pcodeOpIterator.hasNext()){
                PcodeOp pcodeOp = pcodeOpIterator.next();
                if(pcodeOp.equals(grandParentInst)){
                    continue; // Skip the grandparent instruction to avoid deadlock
                }
                String mnem = pcodeOp.getMnemonic();
                if(mnem.equals("CALL")){
                    RILLog.debugLog(TAG + "candidate: " + pcodeOp.toString());
                    Function candidateFunc = FunctionUtil.getFunctionWith(program, pcodeOp.getInput(0).getAddress());
                    if(isOpenFunc(candidateFunc)){
                        Varnode[] inputs = pcodeOp.getInputs();
                        for(int i = 1; i < inputs.length; i++){
                            if(PCodeUtil.evaluateVarNode(inputs[i]).equals(PCodeUtil.evaluateVarNode(strNodeRep))){
                                binaryString.add2OpenOp(pcodeOp);
                                return;
                            }
                        }
                    }
                }
            }
            return;
        } else if(calledFunc.toString().equals("strcpy")){ // Handle the strcpy function which is similar to COPY operation
            Varnode dest = inst.getInput(1);
            if(!dest.equals(node)){
                Function func = dest.getHigh().getHighFunction().getFunction();
                RILLog.debugLog(TAG + "call strcpy and continue to taint dest " + dest.toString() + " in the func " + func.toString());
                // Continue tainting the destination
                taintToOpen(func, dest, binaryString);
            }
        } else {
            // Handle cases where the function is not recognized
            int i = 1;
            int skipped = 0;
            for(; i < inst.getNumInputs(); i++){
                // Skip stack variables not defined in the function prototype
                String nodeStr = PCodeUtil.evaluateVarNode(inst.getInput(i));
                RILLog.debugLog(TAG + "input " + i + " evaluate: " + nodeStr);
                if(nodeStr.contains(Global.STACK_REG)){
                    skipped++;
                }
                // Handle the target node if known
                if(node != null){
                    if(inst.getInput(i).equals(node)){
                        break;
                    }
                // For unknown target node, use constant value
                } else if(inst.getInput(i).toString().contains("0x" + binaryString.getAddress().toString().replaceFirst("^0+(?!$)", ""))){
                    break;
                }
            }
            RILLog.debugLog(TAG + "forward to calledFunction " + calledFunc.toString() + " with paramIdx " + i + " and skip " + skipped);
            taintToOpenByCall(calledFunc, i - skipped, binaryString);
        }
        // Remove the current CALL instruction from the call stack
        if(!callStack.isEmpty())
            callStack.remove(callStack.size() - 1);
    }

    private void handleStore(Function func, PcodeOp inst, BinaryString binaryString){
        String TAG = "[handleStore] ";
        RILLog.debugLog(TAG + inst.toString());

        // Retrieve the offset node from the STORE instruction
        Varnode node = inst.getInput(1);
        RILLog.debugLog(TAG + "offsetNode: " + node.toString());
        handleStoreOffset(func, node, binaryString);
    }

    private void handleStoreOffset(Function func, Varnode node, BinaryString binaryString){
        String TAG = "[handleStoreOffset] ";
        if(node.isRegister()){
            String nodeName = node.getHigh().getName();
            RILLog.debugLog(TAG + "offsetNode Name: " + nodeName);
            int nodeParamIndex = PCodeUtil.getNodeParamIndex(node);
            RILLog.debugLog(TAG + "nodeParamIndex: " + nodeParamIndex);
            if(nodeParamIndex >= 0){
                // Process references to the function address
                Address funcAddr = func.getEntryPoint();
                ReferenceIterator referenceIterator = AddressUtil.getReferenceToAddress(program, funcAddr);
                while(referenceIterator.hasNext()){
                    Reference reference = referenceIterator.next();
                    Function refFunc = FunctionUtil.getFunctionWith(program, reference.getFromAddress());
                    RILLog.debugLog(TAG + "refFunc: " + refFunc.toString());
                    HighFunction hf = Global.getDecompFunc(refFunc).getHighFunction();
                    Iterator<PcodeOpAST> pcodes =  hf.getPcodeOps();
                    while(pcodes.hasNext()){
                        PcodeOp pcode = pcodes.next();
                        String mnem = pcode.getMnemonic();
                        Varnode funcNode = pcode.getInput(1);
                        Address calleeAddr = funcNode.getAddress();
                        if(mnem.equals("CALL") && funcAddr.equals(calleeAddr)){
                            RILLog.debugLog(TAG + "candidate call: " + pcode.toString());
                            Varnode targetNode = pcode.getInput(nodeParamIndex + 1);
                            RILLog.debugLog(TAG + "targetNode: " + targetNode);
                            handleStoreOffset(func, targetNode, binaryString);
                        }
                    }
                }
                return;
            } else {
                RILLog.debugLog(TAG + "node is register but not param");
            }
        }
        if(node.isUnique() || node.isRegister()){
            String exp = PCodeUtil.evaluateVarNode(node);
            RILLog.debugLog(TAG + "node exp: " + exp);
            ArrayList<Function> siblingFuncs = new ArrayList<Function>();
            ArrayList<Function> siblingFuncs2 = new ArrayList<Function>();
            siblingFuncs.add(func);
            Namespace namespace = func.getParentNamespace();
            if(!namespace.isGlobal()){
                FunctionIterator classMethods = program.getFunctionManager().getFunctions(namespace.getBody(), true);
                while(classMethods.hasNext()){
                    Function sibling = classMethods.next();
                    if(sibling.equals(func)){
                        RILLog.debugLog(TAG + "ignore existing");
                        continue;
                    }
                    if(sibling.toString().contains("::~")){
                        RILLog.debugLog(TAG + "ignore destructor");
                        continue;
                    }
                    if(FunctionUtil.havePriKeyword(sibling.getName())){
                        siblingFuncs.add(sibling);
                    } else {
                        siblingFuncs2.add(sibling);
                    }
                }
                siblingFuncs.addAll(siblingFuncs2);
            }
            for(Function sibling : siblingFuncs){
                RILLog.debugLog(TAG + "analyze sibling " + sibling.toString());

                HighFunction hf = Global.getDecompFunc(sibling).getHighFunction();
                Iterator<PcodeOpAST> pcodes = hf.getPcodeOps();
                while(pcodes.hasNext()){
                    PcodeOp pcodeOp = pcodes.next();
                    String mnem = pcodeOp.getMnemonic();
                    if(mnem.equals("LOAD")){
                        RILLog.debugLog(TAG + "load inst: " + pcodeOp.toString());
                        Varnode loadOffsetNode = pcodeOp.getInput(1);
                        String dstExp = PCodeUtil.evaluateVarNode(loadOffsetNode);
                        RILLog.debugLog(TAG + "dstExp:" + dstExp);
                        if (dstExp.equals(exp)) { // Check if the expressions match
                            RILLog.debugLog(TAG + "exp match");
                            taintToOpen(sibling, pcodeOp.getOutput(), binaryString);
                        } else {
                            RILLog.debugLog(TAG + "exp not match");
                        }
                    }
                }
            }
        } else {
            RILLog.errorLog(TAG + "store offset is not unique");
            assert 0 > 1; // Error: store offset is not unique
        }
    }


    private ArrayList<Object> trackVarnode2Const(Varnode node){
        String TAG = "[trackVarnode2Const] ";
        RILLog.debugLog(TAG + "track node " + node.toString());

        // If the node is a constant, return it directly
        if(node.isConstant()){
            RILLog.debugLog(TAG + "node is const");
            ArrayList<Object> res = new ArrayList<Object>();
            res.add(node);
            return res;
        }

        // Get the defining PcodeOp of the node
        PcodeOp pcodeOp = node.getDef();
        if(pcodeOp == null){
            RILLog.debugLog(TAG + "def pcodeop is null");
            // If the node's high-level name is "this", treat it as a return value 0
            if(node.getHigh().getName().equals("this")){
                RILLog.debugLog(TAG + "return value 0");
                ArrayList<Object> res = new ArrayList<Object>();
                res.add((Object) 0L);
                return res;
            }else{
                RILLog.debugLog(TAG + "unseen node type");
                assert 0 > 1;
            }
        }else {
            RILLog.debugLog(TAG + "get node Define " + pcodeOp.toString());
            String mnem = pcodeOp.getMnemonic();
            switch (mnem){
                case "CAST":
                    // For CAST operations, track the constant value through the casted input
                    return trackVarnode2Const(pcodeOp.getInput(0));
                case "PTRADD":
                    // For PTRADD operations, handle both space and offset inputs
                    Varnode space  = pcodeOp.getInput(0);
                    Varnode offset = pcodeOp.getInput(1);
                    RILLog.debugLog(TAG + "space: " + space.toString() + " offset: " + offset.toString());
                    if(space.isConstant() || // If space is a constant or points to "this"
                            space.getHigh().getName().equals("this")){  // Register pointing to "this" and offset is in the second input
                        RILLog.debugLog(TAG + "continue to trackVarnode2Const");
                        return trackVarnode2Const(offset);
                    }else {
                        RILLog.debugLog(TAG + "call to handleImplicitPTRADD");
                        // Handle implicit PTRADD cases where both inputs have offsets
                        return handleImplicitPTRADD(pcodeOp);
                    }
                case "LOAD":
                    // For LOAD operations, get the loaded value
                    Varnode spaceNode = pcodeOp.getInput(0);
                    RILLog.debugLog(TAG + "space: " + spaceNode.toString());
                    if(spaceNode.isConstant() || spaceNode.getHigh().getName().equals("this")){
                        Varnode loadOffsetNode = pcodeOp.getInput(1);
                        RILLog.debugLog(TAG + "call getLoadLoc");
                        ArrayList<Object> loadLocs = getLoadLoc(loadOffsetNode); // Get locations where the value was loaded from
                        RILLog.debugLog(TAG + "call getStoredValue");
                        ArrayList<Object> loadOutput = getStoredValue(loadLocs, node.getHigh().getHighFunction().getFunction()); // Track stored values at these locations
                        return loadOutput;
                    }else{
                        RILLog.debugLog(TAG + "unseen store space");
                        assert 0 > 1;
                    }
                    break;
                case "CALL":
                    // For CALL operations, handle specific function calls
                    Varnode calledFuncNode = pcodeOp.getInput(0);
                    Address calledFuncAddr = calledFuncNode.getAddress();
                    Function calledFunc = FunctionUtil.getFunctionWith(program, calledFuncAddr);
                    if(calledFunc.toString().equals("operator.new")){
                        // Ignore calls to "operator.new" (memory allocation)
                        RILLog.debugLog(TAG + "ignored new in CALL");
                    }else{
                        RILLog.debugLog(TAG + "unseen call condition");
                        assert 0 > 1;
                    }
                    break;
                default:
                    RILLog.debugLog(TAG + "unseen op");
                    assert 0 > 1;
            }
        }
        return null;
    }

    private ArrayList<Object> getLoadLoc(Varnode node){
        String TAG = "[getLoadLoc] ";
        RILLog.debugLog(TAG + node.toString());
        // Retrieve the location where the value was loaded from
        return trackVarnode2Const(node);
    }

    private ArrayList<Object> getStoredValue(ArrayList<Object> locs, Function func){
        String TAG = "[getStoredValue] ";

        ArrayList<Function> siblingFuncs = new ArrayList<Function>();
        ArrayList<Function> siblingFuncs2 = new ArrayList<Function>();
        siblingFuncs.add(func);
        Namespace namespace = func.getParentNamespace();
        if(!namespace.isGlobal()){
            FunctionIterator classMethods = program.getFunctionManager().getFunctions(namespace.getBody(), true);
            while(classMethods.hasNext()){
                Function sibling = classMethods.next();
                if(sibling.equals(func)){
                    RILLog.debugLog(TAG + "ignore existing");
                    continue;
                }
                if(sibling.toString().contains("::~")){
                    RILLog.debugLog(TAG + "ignore destructor");
                    continue;
                }
                if(FunctionUtil.havePriKeyword(sibling.getName())){
                    siblingFuncs.add(sibling);
                }else{
                    siblingFuncs2.add(sibling);
                }
            }
            siblingFuncs.addAll(siblingFuncs2);
        }

        ArrayList<Object> storedValues = new ArrayList<Object>();
        for(Object loc : locs){
            // Convert the location representation to a comparable value
            Long locValue = getObjectValue(loc);
            RILLog.debugLog(TAG + "try to find STORE which match " + locValue);
            // Find all STORE operations matching the location and retrieve stored values
            RILLog.debugLog(TAG + "call to getSiblingStoredValue");
            ArrayList<Object> storedValuesFromLoc = getSiblingStoredValue(locValue, siblingFuncs);
            RILLog.debugLog(TAG + "find storedValuesFromLoc");
            storedValues.addAll(storedValuesFromLoc);
        }
        RILLog.debugLog(TAG + "finish getStoredValue");
        return storedValues;
    }

    private ArrayList<Object> getSiblingStoredValue(Long loc, ArrayList<Function> siblingFuncs){
        String TAG = "[getSiblingStoredValue] ";
        ArrayList<Object> storedValues = new ArrayList<Object>();
        for(Function sibling : siblingFuncs){
            HighFunction hf = Global.getDecompFunc(sibling).getHighFunction();
            Iterator<PcodeOpAST> pcodes = hf.getPcodeOps();
            if(sibling.toString().contains("::~")){
                RILLog.debugLog(TAG + "ignore destructor");
                continue;
            }

            while (pcodes.hasNext()) {
                PcodeOp pcodeOp = pcodes.next();
                String mnemonic = pcodeOp.getMnemonic();
                if(mnemonic.equals("STORE")){
                    RILLog.debugLog(TAG + "get sibling store op: " + pcodeOp.toString());
                    Varnode spaceNode = pcodeOp.getInput(0);
                    if(spaceNode.isConstant() || spaceNode.getHigh().getName().equals("this")){
                        Varnode offsetNode = pcodeOp.getInput(1);
                        RILLog.debugLog(TAG + "offset: " + offsetNode.toString());

                        // Track the offset node to find matching stored values
                        ArrayList<Object> offsets = trackVarnode2Const(offsetNode);
                        if(offsets != null){
                            for(Object offset : offsets){
                                Long offsetValue = getObjectValue(offset);
                                if(offsetValue == loc){
                                    Varnode storedVarnode = pcodeOp.getInput(2);
                                    RILLog.debugLog(TAG + "offset match and storedVarnode: " + storedVarnode.toString());
                                    // Track the value stored in the location
                                    ArrayList<Object> storedValue = trackVarnode2Const(storedVarnode);
                                    if(storedValue != null){
                                        storedValues.addAll(storedValue);
                                    }
                                }else{
                                    RILLog.debugLog(TAG + "not offsetValue needed and continue");
                                }
                            }
                        }
                    }else{
                        RILLog.debugLog(mnemonic);
                        assert 0 > 1;
                    }
                }
            }
        }
        return storedValues;
    }


    private ArrayList<Object> handleImplicitPTRADD(PcodeOp pcodeOp){
        String TAG = "[handleImplicitPTRADD] ";
        
        // Get the first input of the Pcode operation, which is expected to be a Varnode.
        Varnode space = pcodeOp.getInput(0);
        PcodeOp spaceOp = space.getDef(); // Get the defining Pcode operation of the Varnode.
        String mnem = spaceOp.getMnemonic(); // Get the mnemonic of the defining Pcode operation.
        ArrayList<Object> spaceOffsetNodes = new ArrayList<Object>(); // List to store offsets derived from spaceOp.
        
        RILLog.debugLog(TAG + "handle space " + spaceOp.toString());
        
        switch(mnem){
            case "MULTIEQUAL":
                // Process each input of the MULTIEQUAL operation.
                for(int i = 0; i < spaceOp.getNumInputs(); i++){
                    Varnode node = spaceOp.getInput(i);
                    RILLog.debugLog(TAG + "MULTIEQUAL input " + i + " : " + node.toString());
                    ArrayList<Object> nodeOffsets = trackVarnode2Const(node); // Track offsets for each input Varnode.
                    spaceOffsetNodes.addAll(nodeOffsets); // Add these offsets to the list.
                }
                break;
            default:
                RILLog.debugLog(TAG + "unseen op");
                assert 0 > 1; // Assertion failure if an unexpected operation mnemonic is encountered.
        }

        // Get the second input of the Pcode operation, which is expected to be a Varnode.
        Varnode offset = pcodeOp.getInput(1);
        ArrayList<Object> offsets = trackVarnode2Const(offset); // Track offsets for the second Varnode.

        ArrayList<Object> finalOffsets = new ArrayList<Object>(); // List to store final calculated offsets.
        
        // Compute final offsets by combining space offsets with the given offsets.
        for(Object spaceOffsetNode: spaceOffsetNodes){
            long spaceOffset = getObjectValue(spaceOffsetNode); // Get the value of the space offset.

            for(Object offsetOb: offsets){
                long offsetValue = getObjectValue(offsetOb); // Get the value of the offset.
                RILLog.debugLog(TAG + "spaceoffset: " + spaceOffset + " offset: " + offsetValue);
                finalOffsets.add(spaceOffset + offsetValue); // Add the combined offset to the final list.
            }
        }

        return finalOffsets; // Return the list of final offsets.
    }

    private Long getObjectValue(Object ob){
        String TAG = "[getObjectValue] ";
        
        // Handle case when the object is a Varnode.
        if(ob instanceof Varnode){
            if(((Varnode)ob).isConstant()){
                return ((Varnode)ob).getOffset(); // Return the offset if the Varnode is constant.
            }else{
                RILLog.debugLog(TAG + "unseen load offset is not constant");
                assert 0 > 1; // Assertion failure if the Varnode is not constant.
            }
        // Handle case when the object is a Long.
        }else if (ob instanceof Long){
            return (Long)ob; // Return the Long value directly.
        }else{
            RILLog.debugLog(TAG + "unseen object type");
            assert 0 > 1; // Assertion failure if the object type is unknown.
        }
        return null; // Return null if no valid value is found.
    }

    public boolean isValidCmdChannel(PcodeOp pcodeOp){
        // Check if the Pcode operation is a CALL operation.
        if(pcodeOp.getMnemonic().equals("CALL")) {
            // Iterate through the list of BinaryString objects to see if any contain the Pcode operation.
            for (BinaryString binaryString : binaryStrings) {
                if (binaryString.isOpenOp(pcodeOp)) {
                    return true; // Return true if the Pcode operation is found.
                }
            }
        }
        return false; // Return false if the Pcode operation is not found.
    }

    public boolean verifyFd(HighFunction hf, PcodeOp startPcodeOp, TaintPath taintPath){
        String TAG = "[verifyFd] ";
        
        // Check if taintFd is valid.
        if(taintPath.taintFd != -1){
            ArrayList<Function> siblingFuncs = new ArrayList<>();
            Function func = hf.getFunction();
            Namespace namespace = func.getParentNamespace();
            List<Address> vcallers = VCallUtil.getVCaller(taintPath.taintFdFunc.getEntryPoint()); // Get virtual callers.
            ArrayList<Varnode> fdNodes = new ArrayList<Varnode>(); // List to store file descriptor nodes.

            if(namespace.isGlobal()){
                RILLog.debugLog(TAG + "namespace: global");
                // Iterate through Pcode operations in the high function.
                Iterator<PcodeOpAST> pcodes = hf.getPcodeOps();
                while(pcodes.hasNext()){
                    PcodeOp pcodeOp = pcodes.next();
                    String mnem = pcodeOp.getMnemonic();
                    // Process CALL operations.
                    if(mnem.equals("CALL")){
                        RILLog.debugLog(TAG + "find CALL: " + pcodeOp.toString());
                        Varnode calleeNode = pcodeOp.getInput(0);
                        Address calleeNodeAddr = calleeNode.getAddress();
                        Function calleeFunc = FunctionUtil.getFunctionWith(program, calleeNodeAddr);
                        if(calleeFunc != null){
                            if(calleeFunc.equals(taintPath.taintFdFunc)){
                                Varnode node = pcodeOp.getInput(taintPath.taintFd + 1);
                                fdNodes.add(node); // Add file descriptor node to the list.
                                RILLog.debugLog(TAG + "find next fd: " + node.toString());
                            }
                        }else{
                            RILLog.debugLog(TAG + "fail to get func");
                        }
                    // Process CALLIND operations.
                    }else if(vcallers != null && mnem.equals("CALLIND")){
                        RILLog.debugLog(TAG + "find CALLIND: " + pcodeOp.toString());
                        Long addr = pcodeOp.getSeqnum().getTarget().getUnsignedOffset();
                        if (vcallers.contains(addr)) {
                            Varnode node = pcodeOp.getInput(taintPath.taintFd + 1);
                            fdNodes.add(node); // Add file descriptor node to the list.
                            RILLog.debugLog(TAG + "find next fd: " + node.toString());
                        }
                    }else{
                        continue;
                    }
                }
            }else{ // Handle cases for classes.
                ReferenceIterator refs = AddressUtil.getReferenceToAddress(program, taintPath.taintFdFunc.getEntryPoint());
                while(refs.hasNext()){
                    Reference ref = refs.next();
                    Address fromAddr = ref.getFromAddress();
                    Function fromFunc = FunctionUtil.getFunctionWith(program, fromAddr);
                    if(fromFunc != null && fromFunc.getParentNamespace().equals(namespace)){
                        HighFunction fromHf = Global.getDecompFunc(fromFunc).getHighFunction();
                        Iterator<PcodeOpAST> pcodes = fromHf.getPcodeOps(fromAddr);
                        while(pcodes.hasNext()){
                            PcodeOp pcodeOp = pcodes.next();
                            String mnem = pcodeOp.getMnemonic();
                            if(mnem.equals("CALL")){
                                RILLog.debugLog(TAG + "find CALL: " + pcodeOp.toString());
                                Varnode node = pcodeOp.getInput(taintPath.taintFd + 1);
                                fdNodes.add(node); // Add file descriptor node to the list.
                                RILLog.debugLog(TAG + "find next fd: " + node.toString());
                                break;
                            }
                        }
                    }
                }
                if(vcallers != null){
                    for(Address vcaller : vcallers){
                        Function vFunc = FunctionUtil.getFunctionWith(program, vcaller);
                        if(vFunc != null && vFunc.getParentNamespace().equals(namespace)){
                            HighFunction fromHf = Global.getDecompFunc(vFunc).getHighFunction();
                            Iterator<PcodeOpAST> pcodes = fromHf.getPcodeOps(vcaller);
                            while(pcodes.hasNext()){
                                PcodeOp pcodeOp = pcodes.next();
                                String mnem = pcodeOp.getMnemonic();
                                if(mnem.equals("CALLIND")){
                                    RILLog.debugLog(TAG + "find CALLIND: " + pcodeOp.toString());
                                    Varnode node = pcodeOp.getInput(taintPath.taintFd + 1);
                                    fdNodes.add(node); // Add file descriptor node to the list.
                                    RILLog.debugLog(TAG + "find next fd: " + node.toString());
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // Check if all collected file descriptor nodes are valid.
            for(Varnode fdNode : fdNodes){
                int checkRes = checkValidFd(hf, fdNode, taintPath);
                RILLog.debugLog(TAG + "checkValidFd return " + checkRes);
                if(checkRes == -1){
                    return false; // Return false if any file descriptor check fails.
                }
            }
        }
        return true; // Return true if all checks pass.
    }


    private int checkValidFd(HighFunction hf, Varnode node, TaintPath taintPath){
        String TAG = "[checkValidFd] ";
        // TODO: handle Stack Variables
        if(node.toString().startsWith("(stack")){
            RILLog.errorLog(TAG + "have to handle stack variable");
            return -1;
        }
        if(node.isConstant()){
            RILLog.debugLog(TAG + "node " + node.toString() + " is constant");
            return -1;
        }
        PcodeOp pcodeOp = node.getDef();
        if(pcodeOp == null){
            // node should be a param and continue to taint
            int index = PCodeUtil.getNodeParamIndex(node);
            RILLog.debugLog(TAG + "node has no def, but paramIndex " + index);
            taintPath.updateFd(index);
            taintPath.updateFdFunc(hf.getFunction());
            return 0;
        }
        RILLog.debugLog(TAG + "PcodeOp: " + pcodeOp.toString());
        if(isValidCmdChannel(pcodeOp)){
            RILLog.debugLog(TAG + "valid cmdChannel");
            taintPath.updateFd(-1); // use -1 indicate finished
            RILLog.debugLog(TAG + "valid cmd and stop taint");
            return 1; // valid fd
        }
        String mnem = pcodeOp.getMnemonic();
        switch(mnem){
            case "COPY":
            case "CAST":
                RILLog.debugLog(TAG + "OP copy/cast");
                return checkValidFd(hf, pcodeOp.getInput(0), taintPath);
            case "PTRSUB":
                return checkValidFd(hf, pcodeOp.getInput(0), taintPath);
            case "LOAD":
                String exp = PCodeUtil.evaluateVarNode(pcodeOp.getInput(1));
                ArrayList<Function> siblings = new ArrayList<Function>();
                siblings.add(hf.getFunction());
                Namespace namespace = hf.getFunction().getParentNamespace();
                if(!namespace.isGlobal()){
                    FunctionIterator classMethods = program.getFunctionManager().getFunctions(namespace.getBody(), true);
                    while(classMethods.hasNext()){
                        Function sibling = classMethods.next();
                        if(sibling.equals(hf.getFunction())){
                            continue;
                        }
                        RILLog.debugLog(TAG + "analyze sibling " + sibling.toString());
                        if(sibling.toString().contains("::~")){
                            RILLog.debugLog(TAG + "ignore deconstructor");
                            continue;
                        }
                        siblings.add(sibling);
                    }
                }
                for(Function sibling : siblings){
                    HighFunction siblingHf = Global.getDecompFunc(sibling).getHighFunction();
                    Iterator<PcodeOpAST> pcodes = siblingHf.getPcodeOps();
                    while(pcodes.hasNext()){
                        PcodeOp pcode = pcodes.next();
                        String pcodeMnem = pcode.getMnemonic();
                        if(pcodeMnem.equals("STORE")){
                            RILLog.debugLog(TAG + "store inst: " + pcode.toString());
                            Varnode storeOffsetNode = pcode.getInput(1);
                            String dstExp = PCodeUtil.evaluateVarNode(storeOffsetNode);
                            RILLog.debugLog(TAG + "dstExp:" + dstExp);
                            if (dstExp.equals(exp)) { // Step 1: check if the expressions match
                                RILLog.debugLog(TAG + "exp match");
                                int tempValid = checkValidFd(siblingHf, pcode.getInput(2), taintPath);
                                if(tempValid == 1 || tempValid == 0){
                                    return tempValid;
                                }
                            }else{
                                RILLog.debugLog(TAG + "exp not match");
                            }
                        }
                    }
                }
                break;
            case "CALL":
                Varnode calleeNode = pcodeOp.getInput(0);
                Function calleefunc = FunctionUtil.getFunctionWith(program, calleeNode.getAddress());
                if(calleefunc.toString().equals("operator.new[]")){
                    Iterator<PcodeOp> nodeUsersIter = node.getDescendants();
                    ArrayList<PcodeOp> nodeUsers = new ArrayList<PcodeOp>();
                    while(nodeUsersIter.hasNext()) {
                        nodeUsers.add(nodeUsersIter.next());
                    }
                    for(PcodeOp userPcodeOp : nodeUsers){
                        String userMnem = userPcodeOp.getMnemonic();
                        switch (userMnem){
                            case "CAST":
                                Varnode tempNode = userPcodeOp.getOutput();
                                Iterator<PcodeOp> tempNodeUsersIter = tempNode.getDescendants();
                                ArrayList<PcodeOp> tempNodeUsers = new ArrayList<PcodeOp>();
                                while(tempNodeUsersIter.hasNext()) {
                                    tempNodeUsers.add(tempNodeUsersIter.next());
                                }
                                for(PcodeOp tempNodeUser : tempNodeUsers){
                                    String tempUserMnem = tempNodeUser.getMnemonic();
                                    switch (tempUserMnem){
                                        case "CALL":
                                            Varnode calleeNode1 = tempNodeUser.getInput(0);
                                            Function calleeFunc1 = FunctionUtil.getFunctionWith(program, calleeNode1.getAddress());
                                            if(calleeFunc1.toString().equals("strcpy")){
                                                int tempValid = checkValidFd(hf, tempNodeUser.getInput(2), taintPath);
                                                if(tempValid == 1 || tempValid == 0){
                                                    return tempValid;
                                                }
                                            }
                                            break;
                                        default:
                                            continue;
                                    }
                                }
                        }
                    }
                }
                RILLog.debugLog(TAG + "called Func: " + calleefunc.toString());
                if(Constants.OpenFuncs.contains(calleefunc.toString())){ // call to open but not existing -> invalid
                    Varnode fdNode = pcodeOp.getInput(1);
                    return checkValidFd(hf, fdNode, taintPath);
                }
            case "MULTIEQUAL":
                String nodeExp = PCodeUtil.evaluateVarNode(node);
                int paramNum = hf.getLocalSymbolMap().getNumParams();
                for(int i = 0; i < paramNum; i++){
                    HighParam highParam = hf.getLocalSymbolMap().getParam(0);
                    Varnode paramNode = highParam.getRepresentative();
                    String nodeStr = paramNode.toString();
                    if(nodeExp.contains(nodeStr)){
                        RILLog.debugLog(TAG + "hit param " + i + "(" + nodeStr + ")");
                        return checkValidFd(hf, paramNode, taintPath);
                    }
                }
                RILLog.debugLog(TAG + "no param match");
                break;
            default:
                RILLog.errorLog(TAG + "unseen OP");
        }
        return -1; // invalid fd
    }
}
