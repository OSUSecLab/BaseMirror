package util;

import java.util.regex.*;

/**
 * RegexUtil provides utility methods for extracting information from strings using regular expressions.
 */
public class RegexUtil {

    /**
     * Extracts a substring from the input string that matches the given regular expression pattern.
     *
     * @param s The input string to search within.
     * @param patternStr The regular expression pattern to match.
     * @return The extracted substring if the pattern is found; otherwise, null.
     */
    public static String extractFromRegex(String s, String patternStr) {
        // Define a regular expression pattern to match the offset
        Pattern pattern = Pattern.compile(patternStr);

        // Create a Matcher to find the pattern in the expression
        Matcher matcher = pattern.matcher(s);

        // Check if the pattern is found
        if (matcher.find()) {
            // Group 1 contains the matched value
            String res = matcher.group(1);
            return res;
        } else {
            // Pattern not found
            return null;
        }
    }

    /**
     * Extracts the stack offset from the given string expression using a predefined pattern.
     *
     * @param s The input string containing the expression.
     * @return The extracted stack offset if the pattern matches; otherwise, null.
     */
    public static String extractStackOffsetFromExp(String s) {
        // Define a regular expression pattern to match the stack offset
        // Example pattern: (const, 0x1b1, 4)
        return extractFromRegex(s, "\\(const, (0x[0-9a-fA-F]+), \\d+\\)");
    }
}
