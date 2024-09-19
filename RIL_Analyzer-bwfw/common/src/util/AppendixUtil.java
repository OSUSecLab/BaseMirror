package util;

import analyze.Global;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.string.FoundString;

import java.util.*;

public class AppendixUtil {
    private static Map<Address, List<Address>> vCalls = new HashMap();

    private static void addVCall(Address key, Address value) {
        if (vCalls.containsKey(key)) {
            vCalls.get(key).add(value);
        }
        else {
            List<Address> lst = new ArrayList<>();
            lst.add(value);
            vCalls.put(key, lst);
        }
    }

    public static List<Address> getCalleeAddr(Address address){
        return vCalls.get(address);
    }

    public static ArrayList<Address> getCallerAddr(Address address){
        Iterator<Map.Entry<Address, List<Address>>> iterator = vCalls.entrySet().iterator();
        ArrayList<Address> caller = new ArrayList<>();
        while (iterator.hasNext()) {
            Map.Entry<Address, List<Address>> entry = iterator.next();
            Address key = entry.getKey();
            List<Address> values = entry.getValue();
            if(values.contains(address)){
                caller.add(key);
            }
        }
        return caller;
    }
    // Future work: merge with RIL-Analysis-bw vCallSolver
    public static void tempAppendIndirectCall() {
        String TAG = "[tempAppendIndirectCall] ";
        String flag = "IoChannelReader poller stopped";
        FlatProgramAPI fpa = new FlatProgramAPI(Global.getProgram());
        List<FoundString> strList = fpa.findStrings(null, flag.length(), 1, false, true);
        for (FoundString str : strList) {
            String string = str.getString(Global.getProgram().getMemory());
            if (string.equals(flag)) {
                ReferenceIterator referenceIterator = Global.getProgram().getReferenceManager().getReferencesTo(str.getAddress());
                Address address = null;
                Reference reference = referenceIterator.next();
                address = reference.getFromAddress();
                Function function = FunctionUtil.getFunctionWith(Global.getProgram(), address);
                HighFunction highFunction = Global.getDecompFunc(function).getHighFunction();
                Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps();
                int idx = 0;
                while(pcodeOpASTIterator.hasNext()){
                    PcodeOpAST pcodeOpAST = pcodeOpASTIterator.next();
                    String mnem = pcodeOpAST.getMnemonic();
                    if(mnem.equals("CALL")){
                        Varnode varnode = pcodeOpAST.getInput(0);
                        Function candidateFunc = FunctionUtil.getFunctionWith(Global.getProgram(), varnode.getAddress());
                        if(candidateFunc.toString().equals("memset")){ // hit memset
                            // RILLog.debugLog(TAG + "hit memset: " + pcodeOpAST.toString());
                            Varnode lenNode = pcodeOpAST.getInput(3);
                            if(lenNode.toString().contains("40800")){
                                break;
                            }
                        }
                    }
                }
//                idx = 0;
                while(pcodeOpASTIterator.hasNext()){
                    PcodeOpAST pcodeOpAST = pcodeOpASTIterator.next();
                    String mnem = pcodeOpAST.getMnemonic();
                    if(mnem.equals("CALLIND")){
                        if(idx == 0){
                            idx++;
                            ArrayList<String> funcList = new ArrayList<>();
                            funcList.add("DevIoctlIoChannel::Read");
                            // may have more???
                            for (String funcStr: funcList) {
                                Function func = FunctionUtil.getWrapperFunctionWithName(Global.getProgram(), funcStr);
                                Address k = func.getEntryPoint();
                                Address v = pcodeOpAST.getSeqnum().getTarget();
                                addVCall(k, v);
                            }
                        }else{
                            ArrayList<String> funcList = new ArrayList<>();
                            funcList.add("IpcModem::DoIoChannelRouting");
                            // may have more???
                            for (String funcStr: funcList) {
                                Function func = FunctionUtil.getWrapperFunctionWithName(Global.getProgram(), funcStr);
                                Address k = func.getEntryPoint();
                                Address v = pcodeOpAST.getSeqnum().getTarget();
                                addVCall(k, v);
                            }
                            break;
                        }
                    }
                }
                break;
            }
        }
    }
}
