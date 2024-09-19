package taint;

import analyze.Global;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import util.*;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.TreeSet;

/**
 * Represents a taint trace within a function, capturing taint sources and chains,
 * and resolving taint propagation through references and function calls.
 */
public class TaintTrace {
    public Function func; // Function being analyzed
    public ArrayList<HighSymbol> taintSrc = new ArrayList<HighSymbol>(); // List of taint sources within the function

    public ArrayList<String> taintChains = new ArrayList<String>(); // List of taint chains propagated through the function
    public ArrayList<TaintTrace> taintTar = new ArrayList<TaintTrace>(); // List of taint traces for functions called from this function

    /**
     * Constructs a TaintTrace object for the function at the specified entry address
     * with given parameter indices.
     * 
     * @param func_entry The entry address of the function being analyzed.
     * @param paramIdxs A list of parameter indices to track as taint sources.
     */
    TaintTrace(Address func_entry, ArrayList<Integer> paramIdxs) {
        // Retrieve the function using the entry address
        func = FunctionUtil.getFunctionWith(Global.getProgram(), func_entry);
        RILLog.debugLog("[TaintTrace] Get Function " + func.toString() + " by entrypoint addr " + func_entry.toString());
        HighFunction hf = Global.getDecompFunc(func).getHighFunction();
        LocalSymbolMap localSymbolMap = hf.getLocalSymbolMap();

        // Add parameters as taint sources
        RILLog.debugLog("[TaintTrace] " + func.toString() + " adding taintSrc");
        for (int idx : paramIdxs) {
            HighSymbol highSymbol = localSymbolMap.getParamSymbol(idx);
            RILLog.debugLog("[TaintTrace] " + func.toString() + " adding Idx: " + idx + " with symbol: " + highSymbol.toString());
            taintSrc.add(highSymbol);
        }

        // Process references to the function entry point
        ReferenceIterator refs = AddressUtil.getReferenceToAddress(Global.getProgram(), func_entry);
        RILLog.debugLog("[TaintTrace] " + func.toString() + " handling ref to func entry " + func_entry.toString());
        while (refs.hasNext()) {
            Reference curRef = refs.next();
            RILLog.debugLog("[TaintTrace] " + func.toString() + " handling curRef: " + curRef.toString());
            Address curRefAddr = curRef.getFromAddress();
            RILLog.debugLog("[TaintTrace] " + func.toString() + " get curRef from addr " + curRefAddr.toString());
            if (curRef.isEntryPointReference()) {
                RILLog.debugLog("[TaintTrace] " + func.toString() + " Reach the Entry Point");
                continue;
            } else if (curRef.getReferenceType().isData()) {
                // Handle virtual table references
                RILLog.debugLog("[TaintTrace] " + func.toString() + " Reference from Data(Virtual Table)");
                handleVTableRef(curRefAddr, paramIdxs, taintChains, taintTar);
                continue;
            } else if (curRef.getReferenceType().isIndirect()) {
                // Handle indirect references
                RILLog.debugLog("[TaintTrace] " + func.toString() + " Reference from Indirect(Frame Description Entry Table)");
                handleIndirectRef(curRefAddr);
                continue;
            }
            // Handle generic function references
            Function refFunc;
            HighFunction refHf;
            RILLog.debugLog("[TaintTrace] " + func.toString() + " handle generic");
            try {
                refFunc = FunctionUtil.getFunctionWith(Global.getProgram(), curRefAddr);
                RILLog.debugLog("[TaintTrace] " + func.toString() + " get refFunc: " + refFunc.toString());
                refHf = Global.getDecompFunc(refFunc).getHighFunction();
            } catch (NullPointerException e) {
                RILLog.debugLog("[TaintTrace] " + func.toString() + " Function containing curRefAddr " + curRefAddr + " not found");
                continue;
            }
            // Process tainted parameters in the called function
            TreeSet<Integer> taintedParams = new TreeSet<Integer>();
            Iterator<PcodeOpAST> pcodes = refHf.getPcodeOps(curRefAddr);
            PcodeOpAST callInst = pcodes.next();
            RILLog.debugLog("[TaintTrace] " + func.toString() + " get callInst: " + callInst.toString());
            for (int idx : paramIdxs) {
                Varnode argNode = callInst.getInput(idx + 1);
                RILLog.debugLog("[TaintTrace] " + func.toString() + " idx: " + idx + "with node: " + argNode.toString());
                String chain = PCodeUtil.evaluateVarNode(argNode, refHf, taintedParams);
                RILLog.debugLog("[TaintTrace] " + func.toString() + " get node chain: " + chain);
                taintChains.add(chain);
            }
            // Add new TaintTrace for each tainted parameter
            ArrayList<Integer> parentParamIdxs = new ArrayList<Integer>(taintedParams);
            TaintTrace tar = new TaintTrace(refFunc.getEntryPoint(), parentParamIdxs);
            taintTar.add(tar);
        }
        RILLog.debugLog("[TaintTrace] " + func.toString() + " finish handling ref to func entry " + func_entry.toString());
    }

    /**
     * Handles references from virtual table entries and propagates taint through those references.
     * 
     * @param addr The address being referenced.
     * @param paramIdxs List of parameter indices to track.
     * @param taintChains List to store taint chains.
     * @param taintTar List to store new taint traces.
     */
    private void handleVTableRef(Address addr, ArrayList<Integer> paramIdxs, ArrayList<String> taintChains, ArrayList<TaintTrace> taintTar) {
        ReferenceIterator refs = AddressUtil.getReferenceToAddress(Global.getProgram(), addr);
        RILLog.debugLog("[handleVTableRef] handling ref to addr" + addr.toString());
        while (refs.hasNext()) {
            Reference curRef = refs.next();
            RILLog.debugLog("[handleVTableRef] handling curRef: " + curRef.toString());
            Address curRefAddr = curRef.getFromAddress();
            RILLog.debugLog("[handleVTableRef] get curRef from addr " + curRefAddr.toString());
            Function refFunc;
            HighFunction refHf;
            try {
                refFunc = FunctionUtil.getFunctionWith(Global.getProgram(), curRefAddr);
                RILLog.debugLog("[handleVTableRef] get refFunc: " + refFunc.toString());
                refHf = Global.getDecompFunc(refFunc).getHighFunction();
            } catch (NullPointerException e) {
                RILLog.debugLog("Function containing curRefAddr " + curRefAddr + " not found");
                continue;
            }
            // Process tainted parameters in the called function
            TreeSet<Integer> taintedParams = new TreeSet<Integer>();
            Iterator<PcodeOpAST> pcodes = refHf.getPcodeOps();
            PcodeOpAST callInst = pcodes.next();
            RILLog.debugLog("[handleVTableRef] get callInst: " + callInst.toString());
            for (int idx : paramIdxs) {
                Varnode argNode = callInst.getInput(idx + 1);
                RILLog.debugLog("[handleVTableRef] idx: " + idx + "with node: " + argNode.toString());
                String chain = PCodeUtil.evaluateVarNode(argNode, refHf, taintedParams);
                RILLog.debugLog("[handleVTableRef] get node chain: " + chain);
                taintChains.add(chain);
            }
            ArrayList<Integer> parentParamIdxs = new ArrayList<Integer>(taintedParams);
            TaintTrace tar = new TaintTrace(refFunc.getEntryPoint(), parentParamIdxs);
            taintTar.add(tar);
        }
        RILLog.debugLog("[handleVTableRef] finish handling ref to addr" + addr.toString());
    }

    /**
     * Handles indirect references and logs processing steps.
     * 
     * @param addr The address being referenced.
     */
    private void handleIndirectRef(Address addr) {
        ReferenceIterator refs = AddressUtil.getReferenceToAddress(Global.getProgram(), addr);
        RILLog.debugLog("[handleIndirectRef] handling ref to addr" + addr.toString());
        while (refs.hasNext()) {
            Reference curRef = refs.next();
            RILLog.debugLog("[handleIndirectRef] Wait");
        }
        RILLog.debugLog("[handleIndirectRef] finish handling ref to addr" + addr.toString());
    }
}
