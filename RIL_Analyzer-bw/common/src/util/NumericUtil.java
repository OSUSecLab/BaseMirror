package util;

import ghidra.util.BigEndianDataConverter;
import ghidra.util.LittleEndianDataConverter;

import java.util.*;

/**
 * NumericUtil provides utility methods for handling numeric conversions.
 */
public class NumericUtil {

    /**
     * Converts a long value to its hexadecimal string representation.
     *
     * @param val The long value to convert.
     * @return The hexadecimal string representation of the value.
     */
    public static String longToHexString(long val) {
        return String.format("0x%X", val);
    }

    /**
     * Converts an integer to a byte array using the specified endianness.
     * 
     * Uses Ghidra's LittleEndianDataConverter for little-endian conversion and
     * BigEndianDataConverter for big-endian conversion.
     *
     * @param x The integer value to convert.
     * @param littleEndian If true, converts the integer to a byte array in little-endian order; otherwise, in big-endian order.
     * @return The byte array representing the integer value in the specified endianness.
     */
    public static byte[] intToBytes(int x, boolean littleEndian) {
        if (littleEndian) {
            LittleEndianDataConverter converter = new LittleEndianDataConverter();
            return converter.getBytes(x);
        } else {
            BigEndianDataConverter converter = new BigEndianDataConverter();
            return converter.getBytes(x);
        }
    }
}
