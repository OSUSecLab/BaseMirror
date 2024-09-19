package taint;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import util.RILLog;

import java.util.ArrayList;

public class BinaryString {
    // The string associated with this BinaryString instance.
    String str;

    // The address associated with this BinaryString instance.
    Address address;

    // List of Pcode operations that are associated with this BinaryString.
    ArrayList<PcodeOp> openOps;

    /**
     * Constructor for the BinaryString class.
     * Initializes the BinaryString with a given string and address.
     * 
     * @param str     The string to associate with this BinaryString.
     * @param address The address to associate with this BinaryString.
     */
    public BinaryString(String str, Address address){
        this.str = str;
        this.address = address;
        this.openOps = new ArrayList<PcodeOp>();
    }

    /**
     * Retrieves the offset value of the address associated with this BinaryString.
     * 
     * @return The offset value of the address.
     */
    public long getAddressValue(){
        return address.getOffset();
    }

    /**
     * Retrieves the address associated with this BinaryString.
     * 
     * @return The address associated with this BinaryString.
     */
    public Address getAddress(){ return address; }

    /**
     * Retrieves the string associated with this BinaryString.
     * 
     * @return The string associated with this BinaryString.
     */
    public String getStr(){
        return str;
    }

    /**
     * Adds a Pcode operation to the list of open operations and logs the addition.
     * 
     * @param pcodeOp The Pcode operation to add to the list.
     */
    public void add2OpenOp(PcodeOp pcodeOp){
        String TAG = "[add2OpenOp] ";
        RILLog.debugLog(TAG + pcodeOp);
        openOps.add(pcodeOp);
    }

    /**
     * Checks if a given Pcode operation is in the list of open operations.
     * 
     * @param pcodeOp The Pcode operation to check.
     * @return True if the Pcode operation is in the list, false otherwise.
     */
    public boolean isOpenOp(PcodeOp pcodeOp){
        return openOps.contains(pcodeOp);
    }
}
